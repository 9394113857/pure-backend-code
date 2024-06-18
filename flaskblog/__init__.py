import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_cors import CORS

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

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "practicesession3@gmail.com"
app.config['MAIL_PASSWORD'] = "gpap kwxz sujc qxie"

# Initialize CORS with default options (allowing all origins)
CORS(app)

# Import routes module after app initialization
from flaskblog import routes
