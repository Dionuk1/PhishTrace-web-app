# 🍯 Honeypot Backend API Module

## Overview

Simple backend API for receiving and storing honeypot messages in **JSON file format** (alternative to database).

**Two endpoints:**
1. **POST /api/honeypot/submit.php** - Receive and store messages
2. **GET /api/honeypot/messages.php** - Retrieve stored messages

---

## 📊 Architecture

```
Frontend (honeypot.php)
        ↓
POST request
        ↓
/api/honeypot/submit.php
        ↓
HoneypotJsonStorage class
        ├→ Validate input
        ├→ Detect keywords
        ├→ Extract URLs
        └→ Store in JSON
        ↓
/data/honeypot_messages.json
```

---

## 🔌 API Endpoints

### 1. Submit Message (POST)

**URL:**
```
POST /api/honeypot/submit.php
```

**Request - Form Data:**
```php
POST /api/honeypot/submit.php
Content-Type: application/x-www-form-urlencoded

username=john_doe&message=Your+message+here
```

**Request - JSON:**
```php
POST /api/honeypot/submit.php
Content-Type: application/json

{
  "username": "john_doe",
  "message": "Your message here"
}
```

**Response - Success (201 Created):**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "john_doe",
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": ["verify", "click"],
    "keyword_count": 2,
    "extracted_urls": ["https://malicious.com", "http://phishing.net"],
    "url_count": 2
  }
}
```

**Response - Validation Error (400 Bad Request):**
```json
{
  "success": false,
  "error": "Username must be between 2 and 50 characters"
}
```

**Response - Server Error (500):**
```json
{
  "success": false,
  "message": "Server error: Failed to save message"
}
```

---

### 2. Get Messages (GET)

**URL:**
```
GET /api/honeypot/messages.php
GET /api/honeypot/messages.php?limit=10
```

**Query Parameters:**
- `limit` (optional) - Number of recent messages (default: 20, max: 100)

**Response - Success (200 OK):**
```json
{
  "success": true,
  "total": 42,
  "limit": 20,
  "returned": 15,
  "messages": [
    {
      "id": 1,
      "username": "john_doe",
      "message": "Your message here",
      "timestamp": "2026-04-27 14:30:45",
      "received_at": 1704897045
    },
    ...
  ]
}
```

---

## 💾 JSON File Format

**Location:** `/data/honeypot_messages.json`

**Structure:**
```json
[
  {
    "id": 1,
    "username": "john_doe",
    "message": "Please verify your account here: https://example.com",
    "detected_keywords": ["verify", "click"],
    "keyword_count": 2,
    "extracted_urls": ["https://example.com"],
    "url_count": 1,
    "timestamp": "2026-04-27 14:30:45",
    "received_at": 1704897045
  },
  {
    "id": 2,
    "username": "@suspicious_user",
    "message": "Claim your free reward NOW!!! Click link http://malicious.net",
    "detected_keywords": ["claim", "free", "click"],
    "keyword_count": 3,
    "extracted_urls": ["http://malicious.net"],
    "url_count": 1,
    "timestamp": "2026-04-27 14:35:22",
    "received_at": 1704897322
  }
]
```

---

## � Keyword Detection

**Suspicious Keywords Monitored:**
```
verify, login, urgent, free, click, claim, reward, password
```

**How It Works:**
1. When a message is submitted, the system checks for keywords
2. Keywords are detected case-insensitively
3. Unique keywords found are stored in array
4. Count is calculated
5. Both are returned in response and stored in JSON

**Example:**
```
Message: "Verify your password here: click now for FREE reward!"
Detected: ["verify", "password", "click", "free", "reward"]
Count: 5
```

**Response Includes:**
- `detected_keywords` - Array of found keywords
- `keyword_count` - Total number of unique keywords found

---

## 🔗 URL Detection

**Supported Protocols:**
```
http://, https://
```

**How It Works:**
1. Every message is scanned for URLs
2. Both HTTP and HTTPS links are detected
3. URLs extracted using regex pattern matching
