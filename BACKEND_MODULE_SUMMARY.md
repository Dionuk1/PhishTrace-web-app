# ✅ Backend API Module - Complete Implementation

## Overview

Simple backend module for receiving honeypot messages and storing them in **JSON file format** (alternative to database).

**Status:** ✅ Ready for Use

---

## 📦 What Was Created

### Files Added

**1. API Endpoints** (2 files)
- `/api/honeypot/submit.php` - Receive messages (POST)
- `/api/honeypot/messages.php` - Retrieve messages (GET)

**2. Storage Class** (1 file)
- `/api/honeypot/HoneypotJsonStorage.php` - JSON file handler

**3. Admin Dashboard** (1 file)
- `/admin/honeypot_json.php` - View messages from JSON

**4. Testing Page** (1 file)
- `/api-test.php` - Interactive API testing console

**5. Documentation** (1 file)
- `/API_DOCUMENTATION.md` - Complete API reference

**6. Data Directory** (1 folder)
- `/data/` - Stores honeypot_messages.json

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend                                 │
│  honeypot.php (User Form) / JavaScript Fetch               │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ POST /api/honeypot/submit.php
                   │ {"username": "...", "message": "..."}
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                 API Layer                                   │
│  submit.php ← Validates Input                              │
│          ├→ Detects Keywords                               │
│          ├→ Extracts URLs                                  │
│          └→ Calls HoneypotJsonStorage                      │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│              Storage Layer                                  │
│  HoneypotJsonStorage ← Manages JSON File                   │
│                    ← Keyword Detection                     │
│                    ← URL Extraction                        │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│              Data Storage                                   │
│  /data/honeypot_messages.json ← Persistent Storage         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Data Flow

### Submission Flow
```
1. User fills honeypot form
2. Submits (GET POST or Fetch)
3. Data → /api/honeypot/submit.php
4. Validation:
   - username (2-50 chars)
   - message (5-5000 chars)
5. If valid:
   - Create record with ID, timestamp
   - Save to JSON file
   - Return {success: true, data}
6. If invalid:
   - Return {success: false, error}
```

### Retrieval Flow
```
1. Admin requests /api/honeypot/messages.php?limit=20
2. HoneypotJsonStorage reads JSON file
3. Returns recent messages
4. Response includes: total, limit, returned, messages[]
```

---

## � Keyword Detection

**Suspicious Keywords Monitored (8 keywords):**
```
verify, login, urgent, free, click, claim, reward, password
```

**How It Works:**
1. Message is received via POST
2. System scans for suspicious keywords (case-insensitive)
3. Unique keywords found are stored in array
4. Count is calculated automatically
5. Both returned in response AND stored in JSON

**Example Detection:**
```
Input Message: "Click here to verify your account and claim your free reward!"

Detected Keywords: ["click", "verify", "claim", "free", "reward"]
Keyword Count: 5

Stored in JSON:
{
  "detected_keywords": ["click", "verify", "claim", "free", "reward"],
  "keyword_count": 5
}
```

**Response Includes:**
- `detected_keywords` - Array of found keywords
- `keyword_count` - Total count of unique keywords found

---
## 🔗 URL Extraction

**Supported Protocols:**
```
http://, https://
```

**How It Works:**
1. Message is received via POST
2. System scans for HTTP/HTTPS URLs
3. Unique URLs found are stored in array
4. Count is calculated automatically
5. Both returned in response AND stored in JSON

**Regex Pattern Used:**
```regex
#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i
```

**Example Extraction:**
```
Input Message: "Visit https://example.com or http://phishing.net for details"

Extracted URLs: ["https://example.com", "http://phishing.net"]
URL Count: 2

Stored in JSON:
{
  "extracted_urls": ["https://example.com", "http://phishing.net"],
  "url_count": 2
}
```

**Response Includes:**
- `extracted_urls` - Array of found URLs
- `url_count` - Total count of unique URLs

---
## �🔌 API Endpoints

### Endpoint 1: Submit Message

**Method:** `POST`

**URL:** `/api/honeypot/submit.php`

**Request (JSON):**
```json
{
  "username": "john_doe",
  "message": "Your message here"
}
```

**Request (Form Data):**
```
username=john_doe
message=Your message here
```

**Response Success (201):**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "john_doe",
    "timestamp": "2026-04-27 14:30:45"
  }
}
```
