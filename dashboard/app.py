import os
from flask import Flask
from dotenv import load_dotenv
from shared.models import db, bcrypt

# Load the .env file values into the environment
load_dotenv()

def create_app():
    app = Flask(__name__)

    # Tell Flask where the database is and the secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Connect the db and bcrypt objects to this app
    db.init_app(app)
    bcrypt.init_app(app)

    return app