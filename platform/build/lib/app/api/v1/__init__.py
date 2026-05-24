from flask import Blueprint

from app.api.v1.devices import bp as devices_bp
from app.api.v1.servers import bp as servers_bp
from app.api.v1.ssh_certificates import bp as ssh_certificates_bp

bp = Blueprint("api_v1", __name__)
bp.register_blueprint(devices_bp, url_prefix="/devices")
bp.register_blueprint(servers_bp, url_prefix="/servers")
bp.register_blueprint(ssh_certificates_bp, url_prefix="/ssh-certificates")
