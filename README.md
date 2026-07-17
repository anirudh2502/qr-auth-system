QR Code Authentication System:- A full-stack two-factor authentication system built with Flask and MySQL, featuring TOTP-based verification, QR code account linking, and a secure session-based login flow.

Features:-
Two-factor login using time-based one-time passwords (TOTP), the same mechanism used by Google, GitHub, and banking apps.
QR code generation for linking user accounts to an authenticator app (Google Authenticator, Authy, Microsoft Authenticator).
Passwords stored as secure hashes, never in plain text.
6-digit verification codes that rotate every 30 seconds, validated against the server-stored secret.
Dedicated verification step — login only succeeds after both password and OTP are correct.
Environment-based configuration — database credentials and secret keys kept out of source control via .env.
Session-based authentication flow with logout support.

Technologies used:-
Backend: Python, Flask
Database: MySQL
Frontend: HTML, CSS, JavaScript
Templating: Jinja2
DB Connector: PyMySQL
Authentication: pyotp (TOTP), Werkzeug (password hashing)
QR Generation: qrcode
