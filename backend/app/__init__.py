from flask import Flask

from app.config import Config
from routes.auth import auth_bp
from routes.api import api_bp
from routes.abac import abac_bp


def create_app(config_object=None):
    app = Flask(__name__)
    app.config.from_object(config_object or Config)

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(abac_bp)

    @app.get("/")
    def index():
        return {
            "service": "backend",
            "status": "ok",
        }, 200

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    return app
