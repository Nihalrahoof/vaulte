# Vaultly (Flask + Jinja + PWA)

Features
- Login/register (hashed passwords), per-user storage and access control
- Upload, download, delete PDFs (PDF-only)
- Encrypt sensitive data at rest with Fernet
- Apple-style widget dashboard UI
- Installable PWA (manifest + service worker)

Setup
1) Create and activate a Python 3.10+ venv
2) pip install -r requirements.txt
3) Copy .env.example to .env and set SECRET_KEY and ENCRYPTION_KEY
4) Run:
   export FLASK_APP=app.py
   flask run
   # or: python app.py

Notes
- Files are stored under uploads/<user_id>/ and DB under instance/app.db by default.
- Deploy to a Python host (e.g., Render, Railway, Fly.io) with gunicorn and wsgi.py.

Security
- Use strong SECRET_KEY and ENCRYPTION_KEY in production.
- Serve behind HTTPS so cookies are secure.
