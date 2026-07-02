import os
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv
from shared.models import db, bcrypt

# Load values from .env file
load_dotenv()


def create_app():
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Connect database and bcrypt to app
    db.init_app(app)
    bcrypt.init_app(app)

    # Set up login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access DevGuard.'
    login_manager.login_message_category = 'info'

    # Register all routes
    from dashboard.routes import register_routes
    register_routes(app, login_manager)

    return app


# Entry point — run this file to start the server
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)