# 📨 Honeypot Form - Public Message Interface

## Overview

The **Honeypot Form** is a public-facing page that simulates a legitimate contact/feedback form. It's designed to:

1. **Attract suspicious messages** - Looks like a real service form
2. **Collect data** - Captures username and message text
3. **Analyze threats** - Automatically detects phishing keywords and URLs
4. **Log intelligence** - Stores information for admin analysis

---

## 📍 Access Points

### Public URL
```
http://localhost/socialshield/honeypot.php
```

### Navigation
From the **Home Page** (index.php):
- Click **📨 Send Tip** button in the hero section

### Direct Links
- **Public form:** `/honeypot.php`
- **Admin dashboard:** `/admin/honeypot.php`
- **Live sync:** `/_live_sync/honeypot.php`

---

## 🎨 User Interface

### Form Fields

**1. Username/Email Input**
```
Label: "Your Username or Email"
Placeholder: "e.g., john_doe or john@example.com"
Validation:
  - Required
  - Min 2 characters
  - Max 50 characters
```

**2. Message Textarea**
```
Label: "Your Message"
Placeholder: "Type your message here..."
Validation:
  - Required
  - Min 5 characters
  - Max 5000 characters
  - Live character counter (JavaScript)
```

**3. Submit Button**
```
Label: "📨 Send Message"
Type: Primary button
Action: POST to same page
Disabled after successful submission
```

---

## 💾 Data Processing

### On Form Submission:

1. **Validation**
   - Check both fields are filled
   - Validate length constraints
   - Show error messages if invalid

2. **Backend Processing**
   ```
   POST data → logHoneypotMessage()
     ↓
   Extract URLs
     ↓
   Detect keywords
     ↓
   Calculate risk score
     ↓
   Store in honeypot_logs table
   ```

3. **Response**
   - ✅ Success: "Message sent successfully! Thank you for reaching out."
   - ⚠️ Warning: "Please fill in all fields."
   - ❌ Error: "An error occurred. Please try again."

---

## 🔍 Automatic Analysis

The form automatically:

✅ **Extracts URLs**
- Regex pattern: `https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]`
- Stores as JSON array
- Example: "Check https://evil.com" → `["https://evil.com"]`

✅ **Detects Keywords** (30+)
- Urgency: urgent, act now, limited time
- Verification: verify, confirm, reset password
- Rewards: win, prize, gift, free
- Threats: banned, suspended, security alert
- Stores as JSON array

✅ **Calculates Risk Score** (0-100)
- Base: 10 per keyword
- High-risk bonus: 8 each
- URL bonus: 5 per URL
- Style penalties: ALL CAPS +5, !!!+5

---

## 📊 Database Storage

**Table:** `honeypot_logs`

| Column | Type | Content |
|--------|------|---------|
| id | INT | Auto-increment ID |
| sender_info | VARCHAR(255) | Username/email entered |
| message_text | LONGTEXT | Full message |
| extracted_url | JSON | URLs found in message |
| risk_score | INT | Calculated score (0-100) |
| detected_keywords | JSON | Keywords found |
| created_at | TIMESTAMP | When received |

**Example Record:**
```json
{
  "id": 42,
  "sender_info": "@suspicious_user",
  "message_text": "URGENT! Verify your account now: https://fake-bank.com",
  "extracted_url": ["https://fake-bank.com"],
  "risk_score": 65,
  "detected_keywords": ["verify", "urgent"],
  "created_at": "2026-04-27 14:30:45"
}
```

---

## 🔐 Security Features

✅ **Input Validation**
- Length checks (min/max)
- HTML escaping on output
- Type declarations (strict_types)

✅ **Database Security**
- Prepared statements (no SQL injection)
- Parameterized queries
- JSON encoding for arrays

✅ **User Experience**
- Live character counter
- Inline validation messages
- Disabled submit after success
- Clear success feedback

---

## 📱 UI Features

### Visual Design
- **Centered layout** - Single column focus
- **Card-based** - Professional appearance
- **Bootstrap 5** - Responsive design
- **Simple colors** - Blue/gray palette
- **Icons** - Emoji for visual cues

### Responsive Behavior
- **Desktop:** Full 6-column width (col-md-6)
- **Tablet:** Adjusts to viewport
- **Mobile:** Full width, readable text
- **Touch-friendly:** Large buttons and inputs

### JavaScript Enhancements
- **Character counter** - Real-time update
- **Form state** - Disables after submit
- **Reset link** - "Send another message" option

---

## 🧪 Test Cases

### Test Case 1: Valid Low-Risk Message
```
Username: "john_doe"
Message: "Hi, I have a question about your service."

Result:
✓ Message sent successfully!
✓ Risk Score: 0 (no keywords/URLs)
