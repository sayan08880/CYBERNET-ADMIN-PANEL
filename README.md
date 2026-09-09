# CYBERNET

Internal admin/user workstation — Flask + SQLite.

## Features
- **Admin panel**: Dashboard (users, sessions, activity, security notifications),
  Control (create/block/disable/delete users, reset password, force logout, S-Time),
  Filesystem (TXT files, AF/CF flags, per-user R/W/RW permissions, admin-only delete),
  Messege (WORKP assign work, WhatsApp-style CHAT, REQUEST approve/reject),
  Admin account (change password, security logs, sessions, **admin S-Time**).
- **User panel**: Dashboard, Work (progress updates), Contact (chat with admin/users),
  Account (send requests: password change, CF access, permissions).
- **Security**: hashed passwords (Werkzeug), server-side session tokens (single active
  session, force logout works), CSRF tokens, login rate limiting, S-Time enforcement,
  audit logs, secure file permission checks.

## How to run

```bash
cd cybernet
python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open:

- User login:  http://127.0.0.1:5000/login/user
- Admin login: http://127.0.0.1:5000/login/admin

## Default credentials

| Account | Username | Password |
|---------|----------|----------|
| Admin   | `admin`  | `admin`  |
| New users (created by admin) | `USER01` etc | `user123` |

Both are forced to change the password on first login.

## Admin login time: 6 AM to 11 PM

The admin S-Time (login window) **defaults to 06:00 - 23:00 (6 AM - 11 PM)**.
Logins outside this window are denied and recorded as a security event.

To change it: log in as admin -> **ADMIN** page -> "ADMIN S-TIME (LOGIN WINDOW)"
-> set Start / End -> SET. It applies immediately.

Each user also has their own S-Time, set by admin in **CONTROL**.

## Notes
- Database is created automatically at `data/cybernet.db` on first run.
- Chat is real-time-ish (3s polling). It is server-side stored; enable HTTPS and
  add client-side encryption if you need true E2E.
- For production: set `debug=False` in app.py, serve behind a real WSGI server.
