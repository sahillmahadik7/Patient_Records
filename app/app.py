import os
import re
import uuid
import secrets
import string
from functools import wraps
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from flask_wtf.csrf import CSRFProtect
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from forms import (
    LoginForm,
    PatientRegisterForm,
    DoctorRegisterForm,
    AddPatientForm,
    UploadForm,
    WrittenReportForm
)
from models import db, User, Record, PatientAssignment, WrittenReport

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "patient_login"
login_manager.login_message = "Please log in to continue."

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
)

S3_BUCKET = app.config["S3_BUCKET"]
s3 = boto3.client(
    "s3", region_name=app.config["AWS_REGION"]) if S3_BUCKET else None

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx", "txt"}
MAX_UPLOAD_SIZE = app.config["MAX_CONTENT_LENGTH"]

# File signatures. DOCX is a ZIP-based Office document and TXT has no reliable
# magic number, so TXT is additionally constrained by decoding as UTF-8.
MAGIC = {
    "pdf": [(b"%PDF-", 0)],
    "png": [(b"\x89PNG\r\n\x1a\n", 0)],
    "jpg": [(b"\xff\xd8\xff", 0)],
    "jpeg": [(b"\xff\xd8\xff", 0)],
    "docx": [(b"PK\x03\x04", 0)],
}


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_active or current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def doctor_patient_required(view):
    @wraps(view)
    @login_required
    def wrapped(patient_id, *args, **kwargs):
        if current_user.role != "doctor" or not current_user.is_active:
            abort(403)
        assignment = PatientAssignment.query.filter_by(
            doctor_id=current_user.id, patient_id=patient_id
        ).first()
        if not assignment:
            abort(403)
        return view(patient_id, *args, **kwargs)
    return wrapped


def allowed_extension(filename):
    return (
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def validate_file_content(file_storage, extension):
    """Check the actual file bytes, not only the filename extension."""
    file_storage.stream.seek(0)
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)

    if extension in MAGIC:
        return any(head.startswith(sig) for sig, _ in MAGIC[extension])

    if extension == "txt":
        try:
            sample = file_storage.stream.read(4096)
            file_storage.stream.seek(0)
            sample.decode("utf-8")
            return b"\x00" not in sample
        except UnicodeDecodeError:
            file_storage.stream.seek(0)
            return False

    return False


def storage_key(original_name):
    ext = original_name.rsplit(".", 1)[1].lower()
    return f"medical-reports/{uuid.uuid4().hex}.{ext}"


def save_report(file_storage, key, content_type):
    if S3_BUCKET:
        file_storage.stream.seek(0)
        s3.upload_fileobj(
            file_storage.stream,
            S3_BUCKET,
            key,
            ExtraArgs={
                "ContentType": content_type,
                "ServerSideEncryption": "AES256",
            },
        )
        return

    base = Path(app.config["UPLOAD_DIR"])
    target = base / key
    target.parent.mkdir(parents=True, exist_ok=True)
    file_storage.save(target)


def delete_report(key):
    if S3_BUCKET:
        try:
            s3.delete_object(Bucket=S3_BUCKET, Key=key)
        except (BotoCoreError, ClientError):
            app.logger.exception("Failed to delete S3 object")
    else:
        target = Path(app.config["UPLOAD_DIR"]) / key
        try:
            target.unlink()
        except FileNotFoundError:
            pass


def send_report(record):
    if S3_BUCKET:
        try:
            url = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": S3_BUCKET, "Key": record.storage_key},
                ExpiresIn=60,
            )
            return redirect(url)
        except (BotoCoreError, ClientError):
            app.logger.exception("Failed to create report download URL")
            abort(404)

    target = Path(app.config["UPLOAD_DIR"]) / record.storage_key
    if not target.is_file():
        abort(404)
    return send_file(
        target,
        as_attachment=True,
        download_name=record.orig_filename,
        mimetype=record.content_type,
    )


def doctor_can_access_patient(patient_id):
    return PatientAssignment.query.filter_by(
        doctor_id=current_user.id, patient_id=patient_id
    ).first() is not None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "script-src 'self'"
    )
    if request.is_secure or app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/")
def index():
    return render_template("index.html")


def generate_patient_code():
    """Generate a non-guessable public patient identifier."""
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(20):
        code = "PAT-" + "".join(secrets.choice(alphabet) for _ in range(10))
        if not User.query.filter_by(patient_code=code).first():
            return code
    raise RuntimeError("Could not generate a unique patient ID")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = PatientRegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))
        user = User(
            name=form.name.data.strip(),
            email=email,
            password=generate_password_hash(form.password.data),
            role="patient",
            status="approved",
            patient_code=generate_patient_code(),
        )
        db.session.add(user)
        db.session.commit()
        flash("Patient account created. Please log in.", "success")
        return redirect(url_for("patient_login"))
    return render_template("register.html", form=form)


@app.route("/doctor/register", methods=["GET", "POST"])
def doctor_register():
    form = DoctorRegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        license_id = form.doctor_license.data.strip()
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
            return redirect(url_for("doctor_register"))
        if User.query.filter_by(doctor_license=license_id).first():
            flash("That medical registration ID is already registered.", "danger")
            return redirect(url_for("doctor_register"))

        user = User(
            name=form.name.data.strip(),
            email=email,
            password=generate_password_hash(form.password.data),
            role="doctor",
            status="pending",
            doctor_license=license_id,
        )
        db.session.add(user)
        db.session.commit()
        flash("Doctor access request submitted. An administrator must approve it before login.", "success")
        return redirect(url_for("doctor_login"))
    return render_template("doctor_register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def patient_login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email, role="patient").first()
        if user and user.status == "approved" and check_password_hash(user.password, form.password.data):
            login_user(user, remember=False)
            return redirect(url_for("dashboard"))
        flash("Invalid patient credentials.", "danger")
    return render_template("login.html", form=form, title="Patient Login", doctor=False)


@app.route("/doctor/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def doctor_login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email, role="doctor").first()
        if not user:
            flash("Invalid doctor credentials.", "danger")
        elif user.status == "pending":
            flash("Your doctor account is awaiting administrator approval.", "warning")
        elif user.status == "rejected":
            flash("Your doctor access request was rejected.", "danger")
        elif check_password_hash(user.password, form.password.data):
            login_user(user, remember=False)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid doctor credentials.", "danger")
    return render_template("login.html", form=form, title="Doctor Login", doctor=True)


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email, role="admin").first()
        if user and user.status == "approved" and check_password_hash(user.password, form.password.data):
            login_user(user, remember=False)
            return redirect(url_for("admin_dashboard"))
        flash("Invalid administrator credentials.", "danger")
    return render_template("login.html", form=form, title="Administrator Login", doctor=False)


@app.post("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))

    if current_user.role == "doctor":

        assignments = PatientAssignment.query.filter_by(
            doctor_id=current_user.id
        ).all()

        patients = [assignment.patient for assignment in assignments]

        records = Record.query.filter_by(
            doctor_id=current_user.id
        ).order_by(
            Record.uploaded_at.desc()
        ).all()

        return render_template(
            "dashboard_doctor.html",
            patients=patients,
            records=records
        )

    records = Record.query.filter_by(
        patient_id=current_user.id
    ).order_by(
        Record.uploaded_at.desc()
    ).all()

    return render_template(
        "dashboard_patient.html",
        records=records
    )


@app.route("/doctor/add-patient")
@role_required("doctor")
def add_patient_page():

    assignments = PatientAssignment.query.filter_by(
        doctor_id=current_user.id
    ).all()

    patients = [
        assignment.patient
        for assignment in assignments
    ]

    return render_template(
        "add_patient.html",
        patients=patients,
        form=AddPatientForm()
    )


@app.route("/doctor/patients")
@role_required("doctor")
def doctor_patients():

    assignments = PatientAssignment.query.filter_by(
        doctor_id=current_user.id
    ).all()

    patients = [
        assignment.patient
        for assignment in assignments
    ]

    return render_template(
        "doctor_patients.html",
        patients=patients
    )


@app.post("/doctor/patients/add")
@role_required("doctor")
def add_patient():

    form = AddPatientForm()

    if not form.validate_on_submit():
        flash("Enter a valid patient ID.", "danger")
        return redirect(url_for("add_patient_page"))

    patient_code = form.patient_code.data.strip().upper()

    patient = User.query.filter_by(
        patient_code=patient_code,
        role="patient",
        status="approved"
    ).first()

    if not patient:
        flash(
            "No approved patient was found with that patient ID.",
            "danger"
        )
        return redirect(url_for("add_patient_page"))

    existing = PatientAssignment.query.filter_by(
        doctor_id=current_user.id,
        patient_id=patient.id
    ).first()

    if existing:
        flash(
            "This patient is already in your patient list.",
            "info"
        )
        return redirect(url_for("add_patient_page"))

    db.session.add(
        PatientAssignment(
            doctor_id=current_user.id,
            patient_id=patient.id
        )
    )

    db.session.commit()

    flash(
        f"Patient {patient.name} was added to your patient list.",
        "success"
    )

    return redirect(url_for("add_patient_page"))


@app.route("/doctor/patients/<int:patient_id>")
@doctor_patient_required
def doctor_patient(patient_id):

    patient = User.query.filter_by(
        id=patient_id,
        role="patient",
        status="approved"
    ).first_or_404()

    records = Record.query.filter_by(
        patient_id=patient_id,
        doctor_id=current_user.id
    ).order_by(
        Record.uploaded_at.desc()
    ).all()

    written_reports = WrittenReport.query.filter_by(
        patient_id=patient_id,
        doctor_id=current_user.id
    ).order_by(
        WrittenReport.created_at.desc()
    ).all()

    upload_form = UploadForm()
    report_form = WrittenReportForm()

    return render_template(
        "patient_detail.html",
        patient=patient,
        records=records,
        written_reports=written_reports,
        form=upload_form,
        report_form=report_form
    )


@app.route(
    "/doctor/patients/<int:patient_id>/report",
    methods=["POST"]
)
@doctor_patient_required
def create_written_report(patient_id):

    patient = User.query.filter_by(
        id=patient_id,
        role="patient",
        status="approved"
    ).first_or_404()

    form = WrittenReportForm()

    if form.validate_on_submit():

        report = WrittenReport(
            title=form.title.data.strip(),
            diagnosis=form.diagnosis.data.strip(),
            notes=form.notes.data.strip(),
            patient_id=patient.id,
            doctor_id=current_user.id
        )

        db.session.add(report)
        db.session.commit()

        flash(
            "Medical report created successfully.",
            "success"
        )

    else:
        flash(
            "Please correct the report form and try again.",
            "danger"
        )

    return redirect(
        url_for(
            "doctor_patient",
            patient_id=patient.id
        )
    )


@app.post("/doctor/patients/<int:patient_id>/upload")
@doctor_patient_required
def upload(patient_id):
    form = UploadForm()
    # patient_id in the URL is authoritative; it is checked by doctor_patient_required.
    if not form.validate_on_submit():
        flash("Upload failed. Check the file and try again.", "danger")
        return redirect(url_for("doctor_patient", patient_id=patient_id))

    patient = User.query.filter_by(
        id=patient_id, role="patient", status="approved").first_or_404()
    file = form.file.data
    original = secure_filename(file.filename or "")

    if not original or not allowed_extension(original):
        flash("File type not allowed.", "danger")
        return redirect(url_for("doctor_patient", patient_id=patient_id))

    ext = original.rsplit(".", 1)[1].lower()
    if not validate_file_content(file, ext):
        flash("The file content does not match the selected file type.", "danger")
        return redirect(url_for("doctor_patient", patient_id=patient_id))

    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size <= 0 or size > MAX_UPLOAD_SIZE:
        flash("File must be between 1 byte and 10 MB.", "danger")
        return redirect(url_for("doctor_patient", patient_id=patient_id))

    key = storage_key(original)
    content_type = file.mimetype or "application/octet-stream"

    try:
        save_report(file, key, content_type)
        record = Record(
            storage_key=key,
            orig_filename=original,
            content_type=content_type,
            size_bytes=size,
            patient_id=patient.id,
            doctor_id=current_user.id,
        )
        db.session.add(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        delete_report(key)
        app.logger.exception("Report upload failed")
        flash("The report could not be stored.", "danger")
        return redirect(url_for("doctor_patient", patient_id=patient_id))

    flash("Report uploaded successfully.", "success")
    return redirect(url_for("doctor_patient", patient_id=patient_id))


@app.get("/records/<int:record_id>/download")
@login_required
def download(record_id):
    record = db.session.get(Record, record_id)
    if not record:
        abort(404)

    if current_user.role == "admin":
        pass
    elif current_user.role == "patient":
        if record.patient_id != current_user.id:
            abort(403)
    elif current_user.role == "doctor":
        if record.doctor_id != current_user.id or not doctor_can_access_patient(record.patient_id):
            abort(403)
    else:
        abort(403)

    return send_report(record)


@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    pending = User.query.filter_by(role="doctor", status="pending").order_by(
        User.created_at.asc()).all()
    recent = User.query.order_by(User.created_at.desc()).limit(25).all()
    return render_template("admin_dashboard.html", pending=pending, recent=recent)


@app.post("/admin/doctors/<int:user_id>/<action>")
@role_required("admin")
def review_doctor(user_id, action):
    if action not in {"approve", "reject"}:
        abort(400)

    doctor = User.query.filter_by(id=user_id, role="doctor").first_or_404()
    doctor.status = "approved" if action == "approve" else "rejected"
    db.session.commit()

    flash(
        f"Doctor account {action}d successfully.",
        "success" if action == "approve" else "warning",
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/doctor/records")
@role_required("doctor")
def doctor_records():

    records = Record.query.filter_by(
        doctor_id=current_user.id
    ).order_by(
        Record.uploaded_at.desc()
    ).all()

    written_reports = WrittenReport.query.filter_by(
        doctor_id=current_user.id
    ).order_by(
        WrittenReport.created_at.desc()
    ).all()

    return render_template(
        "doctor_records.html",
        records=records,
        written_reports=written_reports
    )


@app.get("/healthz")
def healthz():
    return "OK", 200


@app.errorhandler(413)
def too_large(_):
    return "File too large. Maximum upload size is 10 MB.", 413


@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created.")


@app.cli.command("create-admin")
def create_admin():
    """Create the initial admin from environment variables."""
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    name = os.getenv("ADMIN_NAME", "Portal Administrator")

    if not email or not password:
        raise RuntimeError(
            "Set ADMIN_EMAIL and ADMIN_PASSWORD before running flask create-admin")

    with app.app_context():
        existing = User.query.filter_by(email=email.lower()).first()
        if existing:
            print("Admin email already exists.")
            return
        admin = User(
            name=name,
            email=email.lower(),
            password=generate_password_hash(password),
            role="admin",
            status="approved",
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin created.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=False)
