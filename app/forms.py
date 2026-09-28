from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf.file import FileAllowed, FileRequired

ALLOWED_EXTENSIONS = ["pdf", "png", "jpg", "jpeg", "docx", "txt"]


class PatientRegisterForm(FlaskForm):
    name = StringField("Full Name", validators=[
                       DataRequired(), Length(max=80)])
    email = StringField("Email", validators=[
                        DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, max=128)]
    )
    submit = SubmitField("Create Patient Account")


class DoctorRegisterForm(FlaskForm):
    name = StringField("Full Name", validators=[
                       DataRequired(), Length(max=80)])
    email = StringField("Professional Email", validators=[
                        DataRequired(), Email(), Length(max=120)])
    doctor_license = StringField(
        "Medical License / Registration ID",
        validators=[
            DataRequired(),
            Length(min=3, max=100),
            Regexp(r"^[A-Za-z0-9./_-]+$",
                   message="Use only letters, numbers, ., /, _, or -.")
        ],
    )
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, max=128)]
    )
    submit = SubmitField("Request Doctor Access")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
                        DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class AddPatientForm(FlaskForm):
    patient_code = StringField(
        "Patient ID",
        validators=[
            DataRequired(),
            Length(min=8, max=20),
            Regexp(
                r"^PAT-[A-Z0-9]+$", message="Enter a valid patient ID, for example PAT-AB12CD34EF.")
        ],
    )
    submit = SubmitField("Add Patient")


class UploadForm(FlaskForm):
    file = FileField(
        "Medical Report",
        validators=[
            FileRequired(),
            FileAllowed(ALLOWED_EXTENSIONS,
                        "Allowed: PDF, PNG, JPG, JPEG, DOCX, TXT.")
        ],
    )
    submit = SubmitField("Upload Report")


class WrittenReportForm(FlaskForm):

    title = StringField(
        "Title",
        validators=[
            DataRequired(),
            Length(min=2, max=200)
        ]
    )

    diagnosis = TextAreaField(
        "Diagnosis",
        validators=[
            DataRequired(),
            Length(min=1, max=10000)
        ]
    )

    notes = TextAreaField(
        "Notes",
        validators=[
            DataRequired(),
            Length(min=1, max=10000)
        ]
    )

    submit = SubmitField("Save Report")
