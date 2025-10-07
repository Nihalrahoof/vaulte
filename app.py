import os
from pathlib import Path
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

from config import Config, INSTANCE_DIR
from models import db, User, Document, Secret
from utils import allowed_file, ensure_user_upload_dir, generate_csrf_token, validate_csrf_token
from encryption import encrypt_value, decrypt_value

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(Config)

    # Ensure ENCRYPTION_KEY is available; generate and persist to instance if missing
    enc_key = app.config.get("ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY")
    if not enc_key:
        key_path = INSTANCE_DIR / "fernet.key"
        if key_path.exists():
            enc_key = key_path.read_text().strip()
        else:
            enc_key = Fernet.generate_key().decode("utf-8")
            key_path.write_text(enc_key)
        app.config["ENCRYPTION_KEY"] = enc_key

    # Init extensions
    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Ensure folders
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    with app.app_context():
        db.create_all()

    # Security headers (basic)
    @app.after_request
    def set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Prevent caching of HTML pages to ensure UI reflects latest state after POST-redirect
        try:
            if resp.mimetype == "text/html":
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Expires"] = "0"
        except Exception:
            pass
        return resp

    # PWA endpoints
    @app.route("/manifest.webmanifest")
    def manifest():
        return app.send_static_file("manifest.webmanifest")

    @app.route("/service-worker.js")
    def service_worker():
        return app.send_static_file("service-worker.js")

    # Routes
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            csrf = request.form.get("csrf_token")
            if not validate_csrf_token(csrf):
                abort(400)
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            if not email or not password:
                flash("Email and password are required.", "danger")
                return redirect(url_for("register"))
            if User.query.filter_by(email=email).first():
                flash("Email already registered.", "danger")
                return redirect(url_for("register"))
            user = User(email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("auth/register.html", csrf_token=generate_csrf_token())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            csrf = request.form.get("csrf_token")
            if not validate_csrf_token(csrf):
                flash("Security check failed. Please try again.", "danger")
                return redirect(url_for("login"))
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=True, duration=timedelta(days=30))
                return redirect(url_for("dashboard"))
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
        return render_template("auth/login.html", csrf_token=generate_csrf_token())

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        docs_count = Document.query.filter_by(user_id=current_user.id).count()
        secrets_count = Secret.query.filter_by(user_id=current_user.id).count()
        recent_docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).limit(4).all()
        return render_template("dashboard.html", docs_count=docs_count, secrets_count=secrets_count, recent_docs=recent_docs)

    @app.route("/documents", methods=["GET", "POST"])
    @login_required
    def documents():
        if request.method == "POST":
            csrf = request.form.get("csrf_token")
            if not validate_csrf_token(csrf):
                flash("Security check failed. Please try again.", "danger")
                return redirect(url_for("documents"))
            title = (request.form.get("title") or "").strip()
            file = request.files.get("file")
            if not title:
                flash("Title is required.", "danger")
                return redirect(url_for("documents"))
            if not file or file.filename == "":
                flash("Please choose a PDF file.", "danger")
                return redirect(url_for("documents"))
            if not allowed_file(file.filename):
                flash("Only PDF files are allowed.", "danger")
                return redirect(url_for("documents"))
            filename = secure_filename(file.filename)
            user_dir = ensure_user_upload_dir(current_user.id)
            stored_name = f"{current_user.id}_{Document.query.filter_by(user_id=current_user.id).count()+1}_{filename}"
            try:
                file.save(os.path.join(user_dir, stored_name))
            except Exception as e:
                flash(f"Failed to save file: {e}", "danger")
                return redirect(url_for("documents"))
            doc = Document(
                user_id=current_user.id,
                title=title,
                stored_filename=stored_name,
                original_filename=filename,
            )
            db.session.add(doc)
            db.session.commit()
            flash("Document uploaded.", "success")
            return redirect(url_for("documents"))

        docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
        return render_template("documents.html", docs=docs, csrf_token=generate_csrf_token())

    @app.route("/documents/<int:doc_id>/download")
    @login_required
    def download_document(doc_id: int):
        doc = Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()
        user_dir = ensure_user_upload_dir(current_user.id)
        return send_from_directory(user_dir, doc.stored_filename, as_attachment=True, download_name=doc.original_filename)

    @app.route("/documents/<int:doc_id>/view")
    @login_required
    def view_document(doc_id: int):
        doc = Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()
        user_dir = ensure_user_upload_dir(current_user.id)
        # Serve inline for browser PDF rendering
        return send_from_directory(
            user_dir,
            doc.stored_filename,
            as_attachment=False,
            download_name=doc.original_filename,
            mimetype="application/pdf",
        )

    @app.route("/documents/<int:doc_id>/delete", methods=["POST"])
    @login_required
    def delete_document(doc_id: int):
        csrf = request.form.get("csrf_token")
        if not validate_csrf_token(csrf):
            flash("Security check failed. Please try again.", "danger")
            return redirect(url_for("documents"))
        doc = Document.query.filter_by(id=doc_id, user_id=current_user.id).first_or_404()
        user_dir = ensure_user_upload_dir(current_user.id)
        path = os.path.join(user_dir, doc.stored_filename)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        db.session.delete(doc)
        db.session.commit()
        flash("Document deleted.", "success")
        return redirect(url_for("documents"))

    @app.route("/secrets", methods=["GET", "POST"])
    @login_required
    def secrets():
        if request.method == "POST":
            csrf = request.form.get("csrf_token")
            if not validate_csrf_token(csrf):
                flash("Security check failed. Please try again.", "danger")
                return redirect(url_for("secrets"))
            label = (request.form.get("label") or "").strip()
            value = (request.form.get("value") or "").strip()
            if not label or not value:
                flash("Both label and value are required.", "danger")
                return redirect(url_for("secrets"))
            enc = encrypt_value(value)
            s = Secret(user_id=current_user.id, label=label, enc_value=enc)
            db.session.add(s)
            db.session.commit()
            flash("Secret saved securely.", "success")
            return redirect(url_for("secrets"))
        items = Secret.query.filter_by(user_id=current_user.id).order_by(Secret.created_at.desc()).all()
        # Decrypt for display; consider masking in a production app
        decrypted = [(i.id, i.label, decrypt_value(i.enc_value)) for i in items]
        return render_template("secrets.html", secrets=decrypted, csrf_token=generate_csrf_token())

    @app.route("/secrets/<int:secret_id>/delete", methods=["POST"])
    @login_required
    def delete_secret(secret_id: int):
        csrf = request.form.get("csrf_token")
        if not validate_csrf_token(csrf):
            flash("Security check failed. Please try again.", "danger")
            return redirect(url_for("secrets"))
        s = Secret.query.filter_by(id=secret_id, user_id=current_user.id).first_or_404()
        db.session.delete(s)
        db.session.commit()
        flash("Secret deleted.", "success")
        return redirect(url_for("secrets"))

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))  # Default to 5000 if PORT is not set
    app.run(host='0.0.0.0', port=port)
