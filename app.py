# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session , send_file , jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from urllib.parse import urlparse
import pika
from pika import SSLOptions
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from pymongo import MongoClient
from bson import ObjectId
from io import BytesIO
from PIL import Image
from passlib.hash import sha256_crypt
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from flask_socketio import SocketIO, emit
from flask_socketio import join_room, leave_room
import os



ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

key = Fernet.generate_key()
print(key)
cipher_suite = Fernet(key)
print(cipher_suite)
socketio = SocketIO(app)

postgre_user = os.environ.get('DB_USER')
postgre_password = os.environ.get('DB_PASSWORD')
print(postgre_password)

# Configure PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{postgre_user}:{postgre_password}@database-1.cr64q8k6qvk2.us-east-1.rds.amazonaws.com'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

# User model for PostgreSQL
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    # Define a one-to-many relationship with the 'posts' table
    posts = relationship('Post', backref='user', lazy=True)
  

class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.String(255), nullable=False)
    likes = db.Column(db.Integer, default=0, nullable=False)

    # ForeignKey to establish the relationship with the 'user' table
    user_id = db.Column(db.Integer, db.ForeignKey('user.username'), nullable=False)


class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])



with app.app_context():
    db.create_all()

mongo_user=os.environ.get('MONGO_USER')
mongo_password=os.environ.get('MONGO_PASSWORD')
print(mongo_user)

client = MongoClient(f'mongodb+srv://{mongo_user}:{mongo_password}@my-cluster.xeffwni.mongodb.net/?retryWrites=true&w=majority')
mongo_db = client['sample-db']
photos_collection = mongo_db['sample-col']

# client=MongoClient('localhost')
# mongo_db=client['admin']
# photos_collection = mongo_db['sample-col']



rabbitmq_host = 'shark.rmq.cloudamqp.com'  # Replace with the server's IP address or domain name
rabbitmq_port = 5672  # Default RabbitMQ port
rabbitmq_user = os.environ.get('RABBIT_USER')  # Replace with your RabbitMQ username
rabbitmq_password = os.environ.get('RABBIT_PASSWORD')  # Replace with your RabbitMQ password

connection = pika.BlockingConnection(pika.ConnectionParameters(
    host= 'shark.rmq.cloudamqp.com',
    port=5672,
    virtual_host='vdhdsfym',
    connection_attempts=3,  # Number of connection attempts before giving up
    retry_delay=5,
    heartbeat=1000,
    blocked_connection_timeout=300,
    credentials=pika.PlainCredentials(username=rabbitmq_user, password=rabbitmq_password)
))

channel = connection.channel()



@app.route("/")
def index_page():
    return render_template("index.html")

# Example login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pass= sha256_crypt.hash(password)

        user = User.query.filter_by(username=username).first()

        # if user and check_password_hash(user.password, password):
        if user and sha256_crypt.verify(password, hash_pass):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Example registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = sha256_crypt.hash(password) #generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Example route to display user's photos
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        # Handle the case where 'user_id' is not in the session (redirect, show an error, etc.)
        return redirect('/login')  # Redirect to login page or handle appropriately

    # Fetch user photos based on 'user_id' from the session
    user_photos = photos_collection.find({'user_id': session['user_id']})
    resized_user_photos = []

    for photo in user_photos:
        photo_data = photo['photo']
        resized_photo_data = resize_image(photo_data, max_width=500, max_height=500)
        resized_user_photos.append({'photo': resized_photo_data, 'photo_id': photo['_id']})

    # Render your template with resized_user_photos
    return render_template('dashboard.html', user_id=session['user_id'] ,user_photos=resized_user_photos)


def resize_image(image_data, max_width, max_height):
    with BytesIO(image_data) as image_stream:
        with Image.open(image_stream) as img:
            # Convert the image to the RGB mode if it's in RGBA mode
            if img.mode == 'RGBA':
                img = img.convert('RGB')

            # Resize the image while maintaining the aspect ratio
            img.thumbnail((max_width, max_height))

            # Save the resized image to a BytesIO object
            resized_image_stream = BytesIO()
            img.save(resized_image_stream, format='JPEG')

    return resized_image_stream.getvalue()


@app.route('/logout')
def logout():
    # Your logout logic here
    session.clear()
    return redirect('/login')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle file uploads
@app.route('/upload', methods=['GET', 'POST'])
def upload_photo():
    if request.method == 'POST':
        if 'photo' in request.files:
            photo = request.files['photo']

            # Check if the file has an allowed extension
            if photo and allowed_file(photo.filename):
                try:
                    # Read image content into BytesIO and attempt to open it using PIL
                    image_content = BytesIO(photo.read())
                    img = Image.open(image_content)

                    # If successfully opened, it's a valid image
                    # Now, you can use 'img' for further processing or store it in the database
                    # For example, assuming photos_collection is your MongoDB collection
                    photo_id = photos_collection.insert_one({'photo': image_content.getvalue(), 'user_id': session['user_id']}).inserted_id

                    flash('Photo uploaded successfully!', 'success')
                    return redirect(url_for('dashboard'))
                except Exception as e:
                    flash(f'Error processing image: {str(e)}', 'danger')
            else:
                flash('Invalid file format. Please upload a JPEG or PNG file.', 'danger')

        flash('Error uploading photo!', 'danger')
        return redirect(url_for('dashboard'))

    # If it's a GET request, render the HTML form for photo upload
    return render_template('upload.html')


@app.route('/delete/<photo_id>', methods=['POST'])
def delete_photo(photo_id):
    # Convert the string representation of ObjectId to ObjectId
    photo_id_object = ObjectId(photo_id)

    # Find the photo in the collection based on its ObjectId
    photo_to_delete = photos_collection.find_one({'_id': photo_id_object}) #, 'user_id': session['user_id']})

    if photo_to_delete:
        # If the photo is found, delete it
        photos_collection.delete_one({'_id': photo_id_object}) #, 'user_id': session['user_id']})
        flash('Photo deleted successfully!', 'success')
    else:
        flash('Photo not found or you do not have permission to delete it.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/photos/<photo_id>')
def show_photo(photo_id):
    # Convert the string representation of ObjectId to ObjectId
    photo_id_object = ObjectId(photo_id)

    # Find the photo in the collection based on its ObjectId
    photo_data = photos_collection.find_one({'_id': photo_id_object, 'user_id': session.get('user_id')})

    if photo_data:
        # Assuming 'photo' is the field in your collection storing binary photo data
        return send_file(BytesIO(photo_data['photo']), mimetype='image/jpeg')
    
    return 'Photo not found or you do not have permission to view it.'


# Example route to trigger a like and send a notification
@app.route('/like_photo/<photo_id>')
def like_photo(photo_id):
    notification_message = f'User {session["user_id"]} liked photo {photo_id}'
    channel.basic_publish(exchange='', routing_key='likes', body=notification_message)
    
    flash('Photo liked!', 'success')
    # print(f"User liked photo with ID: {photo_id}")
    # return 'Photo liked!'
    return redirect(url_for('dashboard'))



@app.route('/messages')
def messages():
    # Logic to retrieve all users
    all_users = User.query.all()

    return render_template('messages.html', users=all_users)


@socketio.on('join')
def handle_join(data):
    user_id = data['user_id']
    join_room(user_id)

@socketio.on('message_received')
def handle_message_received(data):
    user_id = data['user_id']
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).all()  # Replace with your function to retrieve messages
    emit('update_messages', {'messages': messages}, room=user_id)


@app.route('/send_message/<user_id>', methods=['POST'])
def send_message(user_id):
    if request.method == 'POST':
        user = User.query.get(user_id)
        message_content = request.form['message_content']

        # encrypted_message = cipher_suite.encrypt(message_content.encode('utf-8'))

        # Create a new message
        new_message = Message(sender_id=session['user_id'], receiver_id=user_id, content=message_content)
        db.session.add(new_message)
        db.session.commit()

        socketio.emit('message_update', {'user_id': session['user_id'], 'content': message_content}, room=user_id)

        # return jsonify(success=True)

    return redirect(url_for('user_messages', user_id=user_id))

@app.route('/user_messages/<user_id>' , methods=['GET', 'POST'])
def user_messages(user_id):
    logged_in_user_id = session.get('user_id')
    
    # Filter messages based on the interaction between logged-in user and the viewed user
    messages = Message.query.filter(
        ((Message.sender_id == logged_in_user_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == logged_in_user_id))
    ).order_by(Message.timestamp).all()

    # Fetch the user whose messages are being viewed
    user = User.query.get(user_id)
    
    # Fetch the logged-in user
    logged_in_user = User.query.get(logged_in_user_id)
    is_ajax_request = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if is_ajax_request:
        # If it's an AJAX request, return only the relevant content
        return jsonify(html=render_template('partial_user_messages.html', user=user, logged_in_user_id=logged_in_user_id, messages=messages))
    else:
        # If it's a regular request, return the entire HTML page
        return render_template('user_messages.html', user=user, logged_in_user_id=logged_in_user_id, messages=messages)

    # Pass both users and messages to the template
    # return render_template('user_messages.html', user=user, logged_in_user_id=logged_in_user_id ,  messages=messages)



if __name__ == '__main__':
    # app.run(debug=True)
    socketio.run(app, debug=True)





# @app.route('/like_post/<post_id>')
# def like_post(post_id):
#     post = Post.query.get(post_id)

#     if post:
#         # Increment the likes count and save the post
#         post.likes += 1
#         db.session.commit()

#         notification_message = f'User {session["user_id"]} liked post {post_id}'
#         channel.basic_publish(exchange='', routing_key='likes', body=notification_message)

#         flash('Post liked!', 'success')
#     else:
#         flash('Post not found!', 'danger')
#     # likes_count = 42  # Replace with the actual likes count
#     # return jsonify({'likes': likes_count})

#     return redirect(url_for('dashboard'))






# @app.route('/send_message/<receiver_id>', methods=['POST'])
# def send_message(receiver_id):
#     if request.method == 'POST':
#         content = request.form.get('content')
#         sender_id = session['user_id']

#         # Save the message to the database
#         message = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
#         db.session.add(message)
#         db.session.commit()

#         flash('Message sent!', 'success')
#         return redirect(url_for('user_dashboard', user_id=receiver_id))
#     else:
#         flash('Invalid request!', 'danger')
#         return redirect(url_for('user_dashboard', user_id=receiver_id))


# @app.route('/dashboard/<user_id>')
# def user_dashboard(user_id):
#     # user_data = User.query.get(user_id)          # here "Session.get()" also works and this is the perfect implementation

#     user_data = db.session.query(User).get(user_id)
#     messages = Message.query.filter(
#         (Message.sender_id == session['user_id'] and Message.receiver_id == user_id) |
#         (Message.sender_id == user_id and Message.receiver_id == session['user_id'])
#     ).order_by(Message.timestamp).all()

#     return render_template('user_dashboard.html', user=user_data, messages=messages)

    # if user_data:
    #     user_posts = photos_collection.find({'user_id': user_data.id})

    # return render_template('user_dashboard.html', user=user_data, user_posts=user_posts)