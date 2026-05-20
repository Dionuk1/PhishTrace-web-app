# PhishTrace - Honeypot Module Integration ✅

## 📍 Lokacioni i Projektit

**Foldera e punës:**
```
dark theme blue old theme/SocialShield/
```

**Ndryshimet e bëra:**
- ✅ Shtuar 10 honeypot functions në `includes/functions.php`
- ✅ Shtuar honeypot dashboard page në `admin/honeypot.php`
- ✅ Shtuar sync copy në `_live_sync/admin/honeypot.php`
- ✅ Integruar link në admin dashboard
- ✅ Ndryshuar emrin "SocialShield" → "PhishTrace" në të gjithë fajllat
- ✅ Database table `honeypot_logs` auto-krijohet kur shfrytëzohet

---

## 🚀 Akseso në Localhost

### Prerequisites
- PHP 8.3+ të instaluar
- MySQL/MariaDB running
- Laragon ose server tjetër lokal
- Database `socialshield` ekziston

### URLs Disponibël

**1. Login**
```
http://localhost/socialshield/login.php
```
- **Username:** student@socialshield.local
- **Password:** (Vendoseni ose përdorni default të database)

Ose admin:
- **Email:** admin@socialshield.local

---

**2. Admin Dashboard**
```
http://localhost/socialshield/admin/dashboard.php
```

Këtu do të shihni seksionin e ri:
- **Security & Monitoring Tools** (seksion i ri)
  - 🍯 Social Media Honeypot (buton i ri)

---

**3. Honeypot Dashboard** ⭐
```
http://localhost/socialshield/admin/honeypot.php
```

### Features në Honeypot Page:

#### 📊 Statistics Cards (4 kolona)
- **Total Messages** - Mesazhet e regjistuar
- **High Risk (>80)** - Mesazhet me risk score > 80
- **Unique IPs** - Numri i dërguuesve unikë
- **Unique URLs** - URLs të ndryshme ekstraktuar

#### 📨 Simulate Honeypot Message Form
Vendosni:
- **Sender Info**: @username, email, ose IP
- **Message Text**: Mesazhi i dyshimtë

Sistemi automatikisht:
- Ekstrakton URLs (http/https)
- Detekton keywords phishing (30+ fjalë)
- Llogarit risk score (0-100)
- Regjistron në database

#### 🟢 Risk Score Visualization
- 🟢 Green (0-49): Low risk
- 🟡 Yellow (50-79): Medium risk
- 🔴 Red (80+): HIGH RISK ALERT

#### 🔑 Top Keywords Detected
Shfaq fjalët më të detektuar me count badges

#### 🔗 Suspicious URLs Extracted
Tabelë me:
- URL teksti
- Sa herë u panë
- Domain ekstraktuar
- Data e parë herën e parë

#### 📋 Recent Activity Table
Shfaq logjat e fundit me:
- Sender info
- Message preview
- Risk score me emoji
- Keywords badges
- URL counter
- Timestamp
- Delete button

#### 🔍 Filter & Search
Filtro sipas:
- Min/Max risk score
- Keyword search

---

## 📝 Test Examples

### Test Case 1: Low Risk
```
Sender: @friend
Message: Hi, how are you doing today?

Result: 
- Keywords: 0
- URLs: 0
- Risk Score: 🟢 0 (Low)
```

### Test Case 2: Medium Risk
```
Sender: @suspicious_account
Message: Please verify your account: https://verify-account.com

Result:
- Keywords: ['verify']
- URLs: ['https://verify-account.com']
- Risk Score: 🟡 ~20 (Medium)
```

### Test Case 3: High Risk ⚠️
```
Sender: @hacker
Message: URGENT!!! Your account BANNED! 
Click NOW: https://fake-bank.com https://recovery.net

Result:
- Keywords: ['urgent', 'banned', 'click']
- URLs: ['https://fake-bank.com', 'https://recovery.net']
- Risk Score: 🔴 70+ (HIGH RISK)
```

---

## 🛡️ Security Features

✅ **CSRF Protection** - Të gjitha formet të mbrojtura
✅ **Admin-Only Access** - Kërkohet login si admin
✅ **SQL Injection Prevention** - Prepared statements
✅ **XSS Prevention** - Output HTML-escaped
✅ **PHP 8.3 Strict Types** - Type declarations mbi të gjitha funksionet

---

## 📊 Database Schema

**Tabela:** `honeypot_logs`
```sql
CREATE TABLE honeypot_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_info VARCHAR(255) NOT NULL,
    message_text LONGTEXT NOT NULL,
    extracted_url JSON,
    risk_score INT DEFAULT 0,
    detected_keywords JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_risk_score (risk_score),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
```

**Shënim:** Tabela krijohet automatikisht në përdorimin e parë!

---

## 🔧 Phishing Keywords Detected (30+)

**Urgency:** urgent, act now, limited time
**Verification:** verify, confirm, reset password, update account
**Rewards:** win, prize, gift, free, claim, bonus, airdrop
**Threats:** banned, suspended, security alert, unusual activity
**Crypto:** wallet, connect wallet, approve, transaction
**Misc:** click, login, congratulations, confirm identity

---

## 📂 File Structure (Dark Theme Folder)

```
dark theme blue old theme/SocialShield/
├── admin/
│   ├── honeypot.php ⭐ NEW
│   ├── dashboard.php (modified - added honeypot link)
│   ├── blacklist.php
│   ├── users.php
│   └── ...
├── includes/
│   ├── functions.php (modified - added 10 honeypot functions)
