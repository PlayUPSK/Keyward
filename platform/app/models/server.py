from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class Server(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "servers"

    hostname = db.Column(db.Text, nullable=False)
    environment = db.Column(db.Text, nullable=False, default="lab")
    status = db.Column(db.Text, nullable=False, default="pending")
    agent_version = db.Column(db.Text)
    public_key = db.Column(db.Text)
    tags = db.Column(db.JSON, nullable=False, default=dict)
    last_seen_at = db.Column(db.DateTime(timezone=True))


class ServerGroup(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "server_groups"

    name = db.Column(db.Text, nullable=False, unique=True)
    description = db.Column(db.Text)


class ServerGroupMember(db.Model):
    __tablename__ = "server_group_members"

    server_id = db.Column(db.Uuid(), db.ForeignKey("servers.id"), primary_key=True)
    group_id = db.Column(db.Uuid(), db.ForeignKey("server_groups.id"), primary_key=True)
