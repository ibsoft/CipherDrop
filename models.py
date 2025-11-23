import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _uuid() -> str:
    return str(uuid.uuid4())


class DataKey(db.Model):
    __tablename__ = "data_keys"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    wrapped_key = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Payload(db.Model):
    __tablename__ = "payloads"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    is_file = db.Column(db.Boolean, default=False, nullable=False)
    filename = db.Column(db.String(255))
    mime_type = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SecretRecord(db.Model):
    __tablename__ = "secret_records"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    share_token = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_salt = db.Column(db.LargeBinary(16), nullable=True)
    password_hash = db.Column(db.LargeBinary(64), nullable=True)
    burn_after_read = db.Column(db.Boolean, default=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    consumed = db.Column(db.Boolean, default=False, nullable=False, index=True)
    consumed_at = db.Column(db.DateTime)
    data_key_id = db.Column(db.String(36), db.ForeignKey("data_keys.id"), nullable=False)
    payload_id = db.Column(db.String(36), db.ForeignKey("payloads.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    data_key = db.relationship(
        "DataKey", cascade="all, delete-orphan", single_parent=True, lazy="joined"
    )
    payload = db.relationship(
        "Payload", cascade="all, delete-orphan", single_parent=True, lazy="joined"
    )
