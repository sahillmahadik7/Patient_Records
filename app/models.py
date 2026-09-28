from datetime import datetime, timezone
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False,
                     default="patient", index=True)
    status = db.Column(db.String(20), nullable=False,
                       default="approved", index=True)
    doctor_license = db.Column(db.String(100), unique=True, nullable=True)
    patient_code = db.Column(db.String(20), unique=True,
                             nullable=True, index=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc))

    uploaded_records = db.relationship(
        "Record", foreign_keys="Record.doctor_id", back_populates="doctor",
        cascade="all, delete-orphan"
    )
    patient_records = db.relationship(
        "Record", foreign_keys="Record.patient_id", back_populates="patient",
        cascade="all, delete-orphan"
    )
    assignments_as_doctor = db.relationship(
        "PatientAssignment", foreign_keys="PatientAssignment.doctor_id",
        back_populates="doctor", cascade="all, delete-orphan"
    )
    assignments_as_patient = db.relationship(
        "PatientAssignment", foreign_keys="PatientAssignment.patient_id",
        back_populates="patient", cascade="all, delete-orphan"
    )

    @property
    def is_active(self):
        return self.status == "approved"

    def can_login(self):
        return self.status == "approved"


class PatientAssignment(db.Model):
    __tablename__ = "patient_assignments"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    patient_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    assigned_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("doctor_id", "patient_id",
                            name="uq_doctor_patient"),
    )

    doctor = db.relationship(
        "User", foreign_keys=[doctor_id], back_populates="assignments_as_doctor"
    )
    patient = db.relationship(
        "User", foreign_keys=[patient_id], back_populates="assignments_as_patient"
    )


class Record(db.Model):
    __tablename__ = "records"

    id = db.Column(db.Integer, primary_key=True)
    storage_key = db.Column(db.String(300), nullable=False, unique=True)
    orig_filename = db.Column(db.String(200), nullable=False)
    content_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    patient_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    doctor_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    patient = db.relationship(
        "User", foreign_keys=[patient_id], back_populates="patient_records"
    )
    doctor = db.relationship(
        "User", foreign_keys=[doctor_id], back_populates="uploaded_records"
    )


class WrittenReport(db.Model):
    __tablename__ = "written_reports"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(
        db.String(200),
        nullable=False
    )

    diagnosis = db.Column(
        db.Text,
        nullable=False
    )

    notes = db.Column(
        db.Text,
        nullable=False
    )

    patient_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    doctor_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    patient = db.relationship(
        "User",
        foreign_keys=[patient_id]
    )

    doctor = db.relationship(
        "User",
        foreign_keys=[doctor_id]
    )
