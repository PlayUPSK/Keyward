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
    from app.auth import bp as auth_bp
    from app.admin import bp as admin_bp
    from app.portal import bp as portal_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")
    app.register_blueprint(auth_bp)
    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")

    from app.cli import register_cli
    from app.security import register_security

    register_cli(app)
    register_security(app)

    from app.services.auth import load_current_user

    app.before_request(load_current_user)

    from app.services.auth import current_user, current_user_roles

    @app.context_processor
    def inject_auth_context():
        return {
            "current_user": current_user(),
            "current_user_roles": current_user_roles,
        }

    return app
