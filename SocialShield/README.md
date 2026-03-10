# SocialShield (PHP University Project)

SocialShield is a beginner-friendly phishing/scam URL detection web app for:
Security and Privacy in Social Networks.

It uses rule-based scoring to classify links as Safe, Suspicious, or Dangerous.

## Tech Stack
- PHP 8.3 (XAMPP PHP 8+)
- MySQL/MariaDB
- HTML, CSS, Bootstrap 5.3
- Vanilla JavaScript
- PDO with prepared statements

## Project Structure
```text
SocialShield/
|-- index.php
|-- scan.php
|-- result.php
|-- history.php
|-- tips.php
|-- login.php
|-- register.php
|-- logout.php
|-- admin/
|   |-- dashboard.php
|   `-- blacklist.php
|-- includes/
|   |-- db.php
|   |-- auth.php
|   |-- functions.php
|   |-- header.php
|   `-- footer.php
|-- assets/
|   |-- css/style.css
|   `-- js/app.js
|-- database/socialshield.sql
`-- README.md
```

## Features
- Home page with intro and call-to-action buttons
- URL scan form with CSRF token
- Rule-based URL risk analysis engine
- Result page with score, status, reasons, and recommendations
- Scan history saved per logged-in user
- Register, login, logout
- Admin dashboard and blacklist management
- Security/privacy tips page from database
- Responsive Bootstrap 5.3 UI

## XAMPP Setup (Windows)
1. Copy folder to `C:\xampp\htdocs\socialshield`
2. Start Apache and MySQL in XAMPP
3. Open `http://localhost/phpmyadmin`
4. Create database `socialshield`
5. Import `database/socialshield.sql`
6. Open `http://localhost/socialshield`

## Database Connection
Edit `includes/db.php` if needed:
- host: `127.0.0.1`
- db: `socialshield`
- user: `root`
- pass: empty (default XAMPP)

## Demo Credentials
- Admin
- Email: `admin@socialshield.local`
- Password: `password`

- User
- Email: `student@socialshield.local`
- Password: `password`

## Detection Rules
- no HTTPS: +20
- long URL: +10
- suspicious keywords: +15
- excessive hyphens: +10
- too many subdomains: +15
- IP address host: +25
- `@` in URL: +20
- blacklisted domain: +50

Thresholds:
- 0 to 20: Safe
- 21 to 49: Suspicious
- 50+: Dangerous

## Example Test URLs
Likely Safe:
- `https://github.com`
- `https://www.linkedin.com/feed/`

Likely Suspicious:
- `http://example.com/login/verify`
- `https://security-alert-account-reset.example.org/urgent/update`

Likely Dangerous:
- `http://192.168.1.22/login@bank-secure-verify.com/reset-password`
- `http://faceb00k-security-alert.com/free-bonus-claim`
- `https://verify-wallet-now.net/claim`

## Notes for Beginners
- `includes/functions.php` has reusable helpers and scan logic.
- `includes/auth.php` handles sessions and access control.
- `admin/blacklist.php` contains admin CRUD with CSRF protection.
- `scans.reasons` stores reasons as JSON text.

## Security Reminder
This is an educational rule-based project and not a full enterprise threat intelligence system.

