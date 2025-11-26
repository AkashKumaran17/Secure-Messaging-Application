from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    chat_codes = db.relationship('ChatCode', backref='user', lazy=True)

class ChatCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.Column(db.String(80), nullable=False)
    image_url = db.Column(db.String(255))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('status', {'msg': f'{current_user.username} has connected'})

@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} has joined the room'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} has left the room'}, room=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    message = data.get('message', '')
    image_url = data.get('image_url')
    
    
    new_message = Message(
        user=current_user.username,
        message=message,
        room=room,
        image_url=image_url
    )
    db.session.add(new_message)
    db.session.commit()
    
    
    emit('message', {
        'user': current_user.username,
        'message': message,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'image_url': image_url
    }, room=room)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/generate_code', methods=['POST'])
@login_required
def generate_code():
    code = secrets.token_hex(3).upper()  
    chat_code = ChatCode(code=code, user_id=current_user.id)
    db.session.add(chat_code)
    db.session.commit()
    return jsonify({'code': code})

@app.route('/enter_chat', methods=['POST'])
@login_required
def enter_chat():
    code = request.form.get('code')
    chat_code = ChatCode.query.filter_by(code=code, is_active=True).first()
    
    if not chat_code:
        flash('Invalid or expired code')
        return redirect(url_for('dashboard'))
    
    
    chat_room = ChatRoom.query.filter_by(code=code).first()
    
    if not chat_room:
        
        chat_room = ChatRoom(code=code, user1_id=current_user.id)
        db.session.add(chat_room)
    else:
        
        if chat_room.user2_id is None and chat_room.user1_id != current_user.id:
            chat_room.user2_id = current_user.id
            chat_code.is_active = False
        else:
            flash('Chat room is full or you are already in it')
            return redirect(url_for('dashboard'))
    
    db.session.commit()
    return redirect(url_for('chat', code=code))

@app.route('/chat/<code>')
@login_required
def chat(code):
    chat_room = ChatRoom.query.filter_by(code=code).first()
    if not chat_room or (current_user.id != chat_room.user1_id and current_user.id != chat_room.user2_id):
        flash('Invalid chat room')
        return redirect(url_for('dashboard'))
    
    
    messages = Message.query.filter_by(room=code).order_by(Message.timestamp).all()
    message_history = [{
        'user': msg.user,
        'message': msg.message,
        'timestamp': msg.timestamp.strftime('%H:%M:%S'),
        'image_url': msg.image_url
    } for msg in messages]
    
    return render_template('chat.html', code=code, message_history=message_history)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image file'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'File type not allowed'})
    
    
    filename = secure_filename(file.filename)
    unique_filename = f"{secrets.token_hex(8)}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(file_path)
        image_url = url_for('static', filename=f'uploads/{unique_filename}')
        return jsonify({'success': True, 'image_url': image_url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True) 