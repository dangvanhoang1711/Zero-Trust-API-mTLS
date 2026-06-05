from flask import Flask

from app.config import Config
from routes.auth import auth_bp
from routes.api import api_bp


def create_app(config_object=None):
    app = Flask(__name__)
    app.config.from_object(config_object or Config)

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    return app
