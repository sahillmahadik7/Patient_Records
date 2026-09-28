# Secure Patient Health Records Portal

Flask application with separate patient/doctor/admin authentication, administrator approval for doctors, patient-doctor assignments, and protected medical-report uploads.

## Security controls

- Parameterized SQL through SQLAlchemy ORM
- Jinja2 output escaping for XSS
- Flask-WTF CSRF protection on state-changing forms
- Server-side role and ownership authorization
- Doctor approval workflow
- Login rate limiting
- Password hashing with Werkzeug
- HttpOnly/SameSite/Secure session-cookie options
- Security headers including CSP, frame protections and MIME sniffing protection
- 10 MB upload limit
- Extension + file-signature validation
- Random storage keys; original filenames are never used as storage paths
- Reports kept outside the static directory for local storage
- Private S3 storage with short-lived presigned download URLs when S3 is configured

## Initial setup

Set `FLASK_SECRET_KEY` before starting.

For local SQLite development:

```bash
pip install -r requirements.txt
flask --app app init-db
set ADMIN_EMAIL=admin@example.com
set ADMIN_PASSWORD=ChangeThisPassword
flask --app app create-admin
flask --app app run
```

For MySQL/RDS set `DATABASE_URL`, for example:

`mysql+pymysql://USER:PASSWORD@HOST/DATABASE`

For S3 set `S3_BUCKET` and `AWS_DEFAULT_REGION`. If S3 is not configured, reports are stored in `private_uploads/` and are still served only through an authorization-checked route.

## Workflow

1. Patients register and can log in immediately.
2. Doctors submit an access request with their medical registration ID.
3. The doctor remains `pending` until an administrator approves the account.
4. An administrator can approve/reject doctor requests.
5. Approved doctors can access only patients assigned to them.
6. Reports are uploaded only from the doctor's patient page.
7. Patients can download only their own reports.
8. Doctors can download only reports belonging to their assigned patients and uploaded by that doctor.
9. Administrators can review portal registrations and access reports when needed.
