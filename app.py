import base64
import hashlib
import io
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

from config_loader import load_secure_config
from crypto_utils import (
    decrypt_payload,
    encrypt_payload,
    generate_data_key,
    load_master_key,
    unwrap_key,
    wrap_key,
)
from forms import EXPIRY_CHOICES, FileSecretForm, PasswordForm, SecretForm
from models import DataKey, Payload, SecretRecord, db

APP_NAME = "CipherDrop"
MAX_TTL = timedelta(days=7)

secure_config = load_secure_config()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY is required for sessions/CSRF")
app.config["PREFERRED_URL_SCHEME"] = "httpS"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 1800
app.config["MAX_CONTENT_LENGTH"] = int(
    secure_config.get("max_upload_mb", 5)) * 1024 * 1024
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///secure_vault.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    app=app,
    default_limits=["120 per hour"],
)

db.init_app(app)

MASTER_KEY = load_master_key("MASTER_KEY")

with app.app_context():
    db.create_all()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)


def _expiry_from_choice(choice: str) -> datetime:
    mapping = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "12h": timedelta(hours=12),
        "1d": timedelta(days=1),
        "3d": timedelta(days=3),
        "7d": timedelta(days=7),
    }
    delta = mapping.get(choice)
    if not delta:
        abort(400)
    target = _utcnow() + delta
    if target - _utcnow() > MAX_TTL:
        abort(400)
    return target


def _validate_file_upload(upload) -> Tuple[bytes, str, str]:
    filename = secure_filename(upload.filename or "")
    if not filename:
        abort(400)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    blocked = set(secure_config.get("blocked_extensions", []))
    if ext in blocked:
        abort(400)
    mime_type = (upload.mimetype or "application/octet-stream").lower()
    allowed_mime = set(m.lower()
                       for m in secure_config.get("allowed_mime_types", []))
    if allowed_mime and mime_type not in allowed_mime:
        abort(400)
    # Read with size guard to avoid unbounded memory.
    stream = upload.stream.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(stream) > app.config["MAX_CONTENT_LENGTH"]:
        abort(413)
    return stream, filename, mime_type


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def _build_qr_image(data: str) -> str:
    import qrcode

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=8,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    b64 = base64.b64encode(buffered.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _purge_expired() -> None:
    now = _utcnow()
    expired = SecretRecord.query.filter(SecretRecord.expires_at <= now).all()
    for record in expired:
        db.session.delete(record)
    if expired:
        db.session.commit()


@app.before_request
def before_request() -> None:
    g.csp_nonce = secrets.token_urlsafe(16)
    _purge_expired()


@app.after_request
def apply_security_headers(response):
    nonce = g.get("csp_nonce", "")
    csp = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "style-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "connect-src 'self'; "
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(410)
@app.errorhandler(413)
@app.errorhandler(500)
def handle_error(err):
    code = getattr(err, "code", 500)
    return render_template("error.html", app_name=APP_NAME, code=code), code


def _persist_secret(
    payload_bytes: bytes,
    is_file: bool,
    filename: Optional[str],
    mime_type: Optional[str],
    expires_at: datetime,
    password: Optional[str],
    burn_after_read: bool,
) -> Tuple[str, str, str]:
    data_key = generate_data_key()
    ciphertext, nonce = encrypt_payload(payload_bytes, data_key)
    wrapped_key, key_nonce = wrap_key(data_key, MASTER_KEY)

    payload = Payload(
        ciphertext=ciphertext,
        nonce=nonce,
        is_file=is_file,
        filename=filename,
        mime_type=mime_type,
    )
    data_key_row = DataKey(wrapped_key=wrapped_key, nonce=key_nonce)

    share_token = _generate_token()
    while SecretRecord.query.filter_by(share_token=share_token).first():
        share_token = _generate_token()

    salt = os.urandom(16) if password else None
    password_hash = _hash_password(password, salt) if password else None

    record = SecretRecord(
        share_token=share_token,
        password_salt=salt,
        password_hash=password_hash,
        burn_after_read=burn_after_read,
        expires_at=expires_at,
        data_key=data_key_row,
        payload=payload,
    )
    db.session.add(record)
    db.session.commit()
    share_url = url_for("view_secret", token=share_token, _external=True)
    # password entry uses same URL; presented separately for scanning
    password_url = share_url
    return share_url, password_url, share_token


def _consume_and_decrypt(record: SecretRecord) -> Tuple[bytes, dict]:
    now = _utcnow()
    updated = (
        db.session.query(SecretRecord)
        .filter(
            SecretRecord.id == record.id,
            SecretRecord.consumed.is_(False),
            SecretRecord.expires_at > now,
        )
        .update({"consumed": True, "consumed_at": now}, synchronize_session=False)
    )
    if updated == 0:
        db.session.rollback()
        abort(410)
    payload = record.payload
    data_key_row = record.data_key
    data_key = unwrap_key(data_key_row.wrapped_key,
                          data_key_row.nonce, MASTER_KEY)
    plaintext = decrypt_payload(payload.ciphertext, payload.nonce, data_key)
    payload_meta = {
        "is_file": payload.is_file,
        "filename": payload.filename,
        "mime_type": payload.mime_type,
    }
    db.session.delete(record)
    db.session.commit()
    return plaintext, payload_meta


@app.route("/", methods=["GET", "POST"])
@limiter.limit("12 per minute", methods=["POST"])
def index():
    secret_form = SecretForm()
    file_form = FileSecretForm()
    qr_share = None
    qr_password = None
    share_token = None
    expires_at = None
    created_type = None
    active_tab = "secret"

    if request.method == "POST":
        target = request.form.get("form_name", "")
        active_tab = "file" if target == "file" else "secret"
        if target == "secret" and secret_form.validate_on_submit():
            expires_at = _expiry_from_choice(secret_form.expires_in.data)
            payload = secret_form.secret_text.data.encode("utf-8")
            share_url, password_url, share_token = _persist_secret(
                payload_bytes=payload,
                is_file=False,
                filename=None,
                mime_type="text/plain",
                expires_at=expires_at,
                password=secret_form.password.data or None,
                burn_after_read=secret_form.burn_after_read.data,
            )
            qr_share = _build_qr_image(share_url)
            qr_password = _build_qr_image(password_url)
            created_type = "Secret"
        elif target == "file" and file_form.validate_on_submit():
            expires_at = _expiry_from_choice(file_form.expires_in.data)
            upload_bytes, filename, mime_type = _validate_file_upload(
                file_form.file.data)
            share_url, password_url, share_token = _persist_secret(
                payload_bytes=upload_bytes,
                is_file=True,
                filename=filename,
                mime_type=mime_type,
                expires_at=expires_at,
                password=file_form.password.data or None,
                burn_after_read=file_form.burn_after_read.data,
            )
            qr_share = _build_qr_image(share_url)
            qr_password = _build_qr_image(password_url)
            created_type = "File"
        else:
            return render_template(
                "index.html",
                app_name=APP_NAME,
                secret_form=secret_form,
                file_form=file_form,
                nonce=g.csp_nonce,
                secure_config=secure_config,
                active_tab=active_tab,
            )
        return render_template(
            "created.html",
            app_name=APP_NAME,
            qr_share=qr_share,
            qr_password=qr_password,
            share_token=share_token,
            expires_at=expires_at,
            nonce=g.csp_nonce,
            created_type=created_type,
        )

    return render_template(
        "index.html",
        app_name=APP_NAME,
        secret_form=secret_form,
        file_form=file_form,
        nonce=g.csp_nonce,
        secure_config=secure_config,
        active_tab=active_tab,
    )


@app.route("/s/<token>", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def view_secret(token: str):
    record = SecretRecord.query.filter_by(share_token=token).first()
    if not record or record.expires_at <= _utcnow():
        if record:
            db.session.delete(record)
            db.session.commit()
        abort(410)
    if record.consumed:
        abort(410)

    form = PasswordForm()
    if request.method == "POST":
        if not form.validate_on_submit():
            abort(400)
        if record.password_hash is not None:
            if not form.password.data:
                abort(401)
            candidate = _hash_password(
                form.password.data, record.password_salt)
            if not secrets.compare_digest(candidate, record.password_hash):
                abort(401)
        plaintext, payload_meta = _consume_and_decrypt(record)
        if payload_meta["is_file"]:
            return send_file(
                io.BytesIO(plaintext),
                mimetype=payload_meta["mime_type"] or "application/octet-stream",
                as_attachment=True,
                download_name=payload_meta["filename"] or "secure.bin",
                max_age=0,
                etag=False,
            )
        return render_template(
            "view_secret.html",
            app_name=APP_NAME,
            secret_text=plaintext.decode("utf-8", errors="replace"),
            nonce=g.csp_nonce,
        )

    require_password = record.password_hash is not None
    return render_template(
        "password_gate.html",
        app_name=APP_NAME,
        form=form,
        require_password=require_password,
        nonce=g.csp_nonce,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
