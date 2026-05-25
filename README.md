# SocialShield

SocialShield is a PHP web app for phishing URL analysis, social-media honeypot monitoring, threat-intelligence ingestion, and AI-assisted risk summaries.

The project combines rule-based scoring, external threat signals (OpenPhish), and operator dashboards for manual review.

## Current Stack
- PHP 8.1+ (tested on local Windows/Laragon setups)
- MySQL or MariaDB
- HTML/CSS, Bootstrap, vanilla JavaScript
- PDO with prepared statements
- Composer dependency: phpoffice/phpword (reporting support)

## Core Features

### URL Scan and Risk Classification
- URL scanning workflow: [scan.php](scan.php) -> [result.php](result.php)
- Rule-based risk engine in [includes/functions.php](includes/functions.php)
- Risk status classification: Safe, Suspicious, Dangerous
- Scan history page for authenticated users: [history.php](history.php)

### AI Security Assistant
- AI summary loading step: [ai_summary_loading.php](ai_summary_loading.php)
- AI summary generation endpoint: [generate_ai_summary.php](generate_ai_summary.php)
- Popup deep-dive report view: [ai_summary_popup.php](ai_summary_popup.php)
- AI report rendering and helper logic in [includes/functions.php](includes/functions.php)

### Admin and Threat Intelligence
- Main admin dashboard: [admin/dashboard.php](admin/dashboard.php)
- Blacklist management: [admin/blacklist.php](admin/blacklist.php)
- Threat intel dashboard with agent controls: [admin/threat_intel.php](admin/threat_intel.php)
- OpenPhish import agents:
	- [agents/openphish_agent.php](agents/openphish_agent.php)
	- [agents/agent_update.php](agents/agent_update.php)

### Honeypot Message Monitoring
- Public/demo honeypot input pages:
	- [honeypot.php](honeypot.php)
	- [honeypot_demo.php](honeypot_demo.php)
- Admin honeypot dashboard: [admin/honeypot_dashboard.php](admin/honeypot_dashboard.php)
- JSON-based honeypot API:
	- Submit: [api/honeypot/submit.php](api/honeypot/submit.php)
	- Messages: [api/honeypot/messages.php](api/honeypot/messages.php)
	- Export CSV: [api/honeypot/export_csv.php](api/honeypot/export_csv.php)
	- Export PDF: [api/honeypot/export_pdf.php](api/honeypot/export_pdf.php)
- Honeypot analysis/storage services in [api/honeypot](api/honeypot)

### Fake Profile Honeypot System
- Admin UI for fake profiles and attacker behavior: [admin/fake_profiles.php](admin/fake_profiles.php)
- Service and repository layer in [api/fake_profiles](api/fake_profiles)
- Tracks repeated senders, keyword patterns, URL activity, and risk levels

### Accounts, Learning, and Gamified Pages
- Authentication: [login.php](login.php), [register.php](register.php), [logout.php](logout.php), [reset_password.php](reset_password.php)
- User profile and settings: [profile.php](profile.php), [settings.php](settings.php)
- Tips and learning pages: [tips.php](tips.php)
- Gamified views: [leaderboard.php](leaderboard.php), [cyber_level.php](cyber_level.php)

### Language Support
- Locale files available in [locales/en.json](locales/en.json) and [locales/sq.json](locales/sq.json)

## Repository Structure (Main App)

```text
socialshield/
|-- index.php
|-- scan.php
|-- result.php
|-- ai_summary_loading.php
|-- generate_ai_summary.php
|-- ai_summary_popup.php
|-- honeypot.php
|-- honeypot_demo.php
|-- history.php
|-- tips.php
|-- login.php
|-- register.php
|-- reset_password.php
|-- profile.php
|-- settings.php
|-- leaderboard.php
|-- cyber_level.php
|-- admin/
|   |-- dashboard.php
|   |-- blacklist.php
|   |-- threat_intel.php
|   |-- honeypot_dashboard.php
|   |-- fake_profiles.php
|   |-- users.php
|   |-- restore_users.php
|   `-- restore_scans.php
|-- api/
|   |-- honeypot/
|   `-- fake_profiles/
|-- agents/
|   |-- openphish_agent.php
|   `-- agent_update.php
|-- includes/
|   |-- db.php
|   |-- auth.php
|   |-- functions.php
|   |-- header.php
|   `-- footer.php
|-- locales/
|   |-- en.json
|   `-- sq.json
|-- database/socialshield.sql
|-- API_DOCUMENTATION.md
|-- HONEYPOT_QUICK_START.md
|-- HONEYPOT_FORM_README.md
`-- README.md
```

## Setup (Windows/Laragon or XAMPP)
1. Place the project inside your web root (for example: C:/laragon/www/socialshield).
2. Start Apache and MySQL/MariaDB.
3. Create a database (commonly named socialshield).
4. Import [database/socialshield.sql](database/socialshield.sql).
5. Install PHP dependencies:

```bash
composer install
```

6. Open the app in your browser (example: http://localhost/socialshield).

## Demo Credentials
- Admin
- Email: `admin@phishtrace.local`
- Password: `Password123!`

- User
- Email: `student@phishtrace.local`
- Password: `Password123!`

## Database Notes
- Base schema and seed data are in [database/socialshield.sql](database/socialshield.sql).
- Additional operational tables (for threat feeds, logs, and module-specific data) may be created by runtime initialization logic in [includes/db.php](includes/db.php).

## API and Module Docs
- Honeypot API reference: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- Backend module overview: [BACKEND_MODULE_SUMMARY.md](BACKEND_MODULE_SUMMARY.md)
- Honeypot quick start: [HONEYPOT_QUICK_START.md](HONEYPOT_QUICK_START.md)
- Honeypot public form guide: [HONEYPOT_FORM_README.md](HONEYPOT_FORM_README.md)

## Notes
- This project is educational and operational for local/lab environments.
- Rule-based and feed-based analysis can produce false positives/negatives and should be reviewed by an operator.
