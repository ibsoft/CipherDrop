# CipherDrop

Zero-trace secret/file sharing with per-item AES-GCM encryption, mandatory expiry, optional passwords, QR-first links, and burn-after-read semantics.

## Prerequisites
- Python 3.10+
- Virtualenv
- System packages: `build-essential libffi-dev python3-dev` (Debian/Ubuntu) for cryptography
- PostgreSQL (recommended) or SQLite for quick start
- `curl` for asset/config downloads
- For QR generation: Pillow (installed via `requirements.txt`)

## Configuration (required)
Generate strong 32-byte keys (base64-url-safe) for master/config/session:
```bash
python - <<'PY'
import base64, secrets
for name in ["MASTER_KEY", "CONFIG_MASTER_KEY", "FLASK_SECRET_KEY"]:
    print(f"{name}={base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}")
PY
```

Set environment variables (example):
```bash
export MASTER_KEY=...
export CONFIG_MASTER_KEY=...
export FLASK_SECRET_KEY=...
export DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cipherdrop   # or sqlite:///secure_vault.db
export PORT=5000
```

Create encrypted config (max upload size, MIME allow/block lists):
```bash
python tools/create_config.py --max-upload-mb 5
```

## Install
```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Run (dev)
```bash
source venv/bin/activate
python app.py
# or with adhoc HTTPS:
FLASK_APP=app.py flask run --cert=adhoc --host 0.0.0.0 --port ${PORT:-5000}
```

## Systemd service (prod)
1) Copy code to `/opt/cipherdrop`, create venv, install deps as above.
2) Place `deploy/cipherdrop.service` into `/etc/systemd/system/cipherdrop.service`.
3) Set environment in `/etc/systemd/system/cipherdrop.service.d/override.conf` (recommended) or export globally:
```
[Service]
Environment="MASTER_KEY=..."
Environment="CONFIG_MASTER_KEY=..."
Environment="FLASK_SECRET_KEY=..."
Environment="DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cipherdrop"
Environment="PORT=5000"
```
4) Reload and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cipherdrop
sudo systemctl status cipherdrop
```

## Nginx reverse proxy with rate limiting
Use `deploy/nginx.conf` as a template:
- Terminates TLS (LetsEncrypt paths shown as placeholders).
- Proxies to `http://127.0.0.1:5000`.
- Separate rate limits: POST create (10r/m, burst 5), GET view (60r/m, burst 30).
- Enforces HTTPS redirect.

Install and enable:
```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/cipherdrop.conf
sudo ln -s /etc/nginx/sites-available/cipherdrop.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Notes
- Do not disable secure cookies in production.
- Keep `MASTER_KEY` and `CONFIG_MASTER_KEY` secret; never commit them.
- Ensure file system permissions restrict `/opt/cipherdrop` and logs to the service user (default `www-data`).
- Run behind HTTPS; HSTS is set at the app and Nginx layers.
