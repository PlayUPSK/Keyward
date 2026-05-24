from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()


def create_app(config_object: str = "app.config.Config") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    migrate.init_app(app, db)

    from app.api.health import bp as health_bp
    from app.api.v1 import bp as api_v1_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    return app
