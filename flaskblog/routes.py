import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import date, datetime, timedelta
from PIL import Image
from flask import (
    Flask, jsonify, request, make_response, url_for, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_mail import Mail, Message
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'

# Initialize SQLAlchemy, Bcrypt, LoginManager, and Mail
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)

# Set up logger configuration
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
current_year = date.today().strftime('%Y')
current_month = date.today().strftime('%m')
year_month_dir = os.path.join(logs_dir, current_year, current_month)
os.makedirs(year_month_dir, exist_ok=True)
log_file = os.path.join(year_month_dir, f'{date.today()}.log')
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Import models and forms
from flaskblog.models import User, Post
from flaskblog.forms import (
    RegistrationForm, LoginForm, UpdateAccountForm, PostForm,
    RequestResetForm, ResetPasswordForm
)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Update with your Gmail username
app.config['MAIL_PASSWORD'] = 'your_password'         # Update with your Gmail password

# Initialize CORS with default options (allowing all origins)
from flask_cors import CORS
CORS(app)

# JWT token generation function
def generate_access_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Send verification email function
def send_verification_email(user):
    token = user.get_verification_token()
    msg = Message('Email Verification', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

# Send password reset email function
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)
    return jsonify({'message': 'Password reset instructions sent'})

# Route for user registration
@app.route("/register", methods=['POST'])
def register():
    if current_user.is_authenticated:
        return jsonify({'message': 'Already authenticated'}), 400
    
    data = request.get_json()
    form = RegistrationForm(username=data.get('username'),
                            email=data.get('email'),
                            password=data.get('password'),
                            confirm_password=data.get('confirm_password'))
    
    if form.validate():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            return jsonify({'message': 'User created successfully'}), 201
        except Exception as e:
            logger.error(f"Error in register route: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        logger.info(f"Validation errors: {form.errors}")
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for verifying email with token
@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    user = User.verify_verification_token(token)
    if user:
        user.verified = True
        db.session.commit()
        return jsonify({'message': 'Email verified'})
    else:
        return jsonify({'message': 'Invalid or expired token'}), 400

# Route for user login
@app.route("/login", methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({'message': 'Already authenticated'}), 400
    data = request.get_json()
    form = LoginForm(email=data.get('email'), password=data.get('password'), remember=data.get('remember', False))
    if form.validate():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                if user.verified:
                    login_user(user, remember=form.remember.data)
                    access_token = generate_access_token(identity=user.id)
                    response = make_response(jsonify({'message': 'Login successful'}), 200)
                    response.set_cookie('x-access-token', access_token, httponly=True)
                    return response
                else:
                    return jsonify({'message': 'Email not verified'}), 401
            else:
                return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            logger.error(f"Error in login route: {str(e)}")
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for user logout
@app.route("/logout")
def logout():
    logout_user()
    response = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    response.delete_cookie('x-access-token')
    return response

# Function to save user profile picture
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

# Route for updating user account details
@app.route("/account", methods=['PUT'])
@login_required
def account():
    data = request.get_json()
    form = UpdateAccountForm(username=data.get('username'), email=data.get('email'), picture=request.files['picture'] if 'picture' in request.files else None)
    if form.validate():
        try:
            if form.picture.data:
                picture_file = save_picture(form.picture.data)
                current_user.image_file = picture_file
            current_user.username = form.username.data
            current_user.email = form.email.data
            db.session.commit()
            return jsonify({'message': 'Account updated successfully'}), 200
        except Exception as e:
            logger.error(f"Error in account route: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for creating a new post
@app.route("/post/new", methods=['POST'])
@login_required
def new_post():
    data = request.get_json()
    form = PostForm(title=data.get('title'), content=data.get('content'))
    if form.validate():
        try:
            post = Post(title=form.title.data, content=form.content.data, author=current_user)
            db.session.add(post)
            db.session.commit()
            return jsonify({'message': 'Post created successfully'}), 201
        except Exception as e:
            logger.error(f"Error in new_post route: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for retrieving a specific post
@app.route("/post/<int:post_id>", methods=['GET'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return jsonify(post.to_dict())

                    
@app.route("/post/<int:post_id>/update", methods=['PUT'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    form = PostForm(title=data.get('title'), content=data.get('content'))
    
    if form.validate():
        try:
            post.title = form.title.data
            post.content = form.content.data
            db.session.commit()
            return jsonify({'message': 'Post updated successfully'}), 200
        except Exception as e:
            logger.error(f"Error in update_post route: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred. Please try again later.'}), 500
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for deleting a specific post
@app.route("/post/<int:post_id>/delete", methods=['DELETE'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        return jsonify({'message': 'Unauthorized'}), 403
    try:
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error in delete_post route: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'An error occurred. Please try again later.'}), 500

# Route for retrieving posts by a specific user
@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return jsonify([post.to_dict() for post in posts.items()])

# Route for requesting password reset
@app.route("/reset_password", methods=['POST'])
def reset_request():
    if current_user.is_authenticated:
        return jsonify({'message': 'Already authenticated'}), 400
    data = request.get_json()
    form = RequestResetForm(email=data.get('email'))
    if form.validate():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        return jsonify({'message': 'Password reset instructions sent'})
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Route for resetting password with token
@app.route("/reset_password/<token>", methods=['PUT'])
def reset_token(token):
    if current_user.is_authenticated:
        return jsonify({'message': 'Already authenticated'}), 400
    user = User.verify_reset_token(token)
    if user is None:
        return jsonify({'message': 'Invalid or expired token'}), 400
    data = request.get_json()
    form = ResetPasswordForm(password=data.get('password'))
    if form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'}), 200
    else:
        return jsonify({'message': 'Validation error', 'errors': form.errors}), 400

# Error handling for 403 Forbidden error
@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({'message': 'Forbidden'}), 403

# Error handling for 404 Not Found error
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'message': 'Not Found'}), 404

# Error handling for 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Rollback any database changes due to the error
    return jsonify({'message': 'Internal Server Error'}), 500



