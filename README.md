# SLSU Document Request System (Flask + SQLite)

## What is implemented
- SQLite schema with normalized tables (up to 3NF).
- Role-based auth foundation (`admin`, `student`).
- Student registration with email OTP verification.
- OTP is 6 digits, expires in 5 minutes, and has max-attempt limits.
- OTP payload is encrypted before database storage.

## Environment setup
1. Update `.env` values:
- `SECRET_KEY`
- `DATA_ENCRYPTION_KEY`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`

2. Install dependencies:
```powershell
c:/Users/HYPERLINK/Music/slsu_document/.venv/Scripts/python.exe -m pip install -r requirements.txt
```

## Run the app
```powershell
c:/Users/HYPERLINK/Music/slsu_document/.venv/Scripts/python.exe app.py
```

## Create admin account (debug script)
```powershell
c:/Users/HYPERLINK/Music/slsu_document/.venv/Scripts/python.exe static/debug/create_admin.py
```

## Registration flow
1. User fills student registration form.
2. App sends OTP to user email.
3. User submits OTP within 5 minutes.
4. Account is created and assigned `student` role.
