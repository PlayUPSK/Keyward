from sqlalchemy.dialects.postgresql import UUID

from app import db
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "users"

    external_id = db.Column(db.Text)
    email = db.Column(db.Text, nullable=False, unique=True)
    display_name = db.Column(db.Text)
    status = db.Column(db.Text, nullable=False, default="active")
    last_login_at = db.Column(db.DateTime(timezone=True))


class Group(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "groups"

    external_id = db.Column(db.Text)
    name = db.Column(db.Text, nullable=False, unique=True)
    source = db.Column(db.Text, nullable=False, default="local")


class UserGroup(db.Model):
    __tablename__ = "user_groups"

    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), primary_key=True)
    group_id = db.Column(UUID(as_uuid=True), db.ForeignKey("groups.id"), primary_key=True)


class Role(UUIDPrimaryKeyMixin, db.Model):
    __tablename__ = "roles"

    name = db.Column(db.Text, nullable=False, unique=True)
    description = db.Column(db.Text)


class RoleBinding(UUIDPrimaryKeyMixin, TimestampMixin, db.Model):
    __tablename__ = "role_bindings"

    subject_type = db.Column(db.Text, nullable=False)
    subject_id = db.Column(UUID(as_uuid=True), nullable=False)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey("roles.id"), nullable=False)
    scope_type = db.Column(db.Text, nullable=False)
    scope_id = db.Column(UUID(as_uuid=True))
