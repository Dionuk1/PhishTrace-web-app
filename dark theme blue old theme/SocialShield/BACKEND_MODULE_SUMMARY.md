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
- `keyword_count` - Total count of unique keywords

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
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": ["verify", "click"],
    "keyword_count": 2
  }
}
```

**Response Error (400):**
```json
{
  "success": false,
  "error": "Username must be between 2 and 50 characters"
}
```

---

### Endpoint 2: Get Messages

**Method:** `GET`

**URL:** `/api/honeypot/messages.php`

**Query Parameters:**
- `limit` (optional, 1-100, default: 20)

**Response Success (200):**
```json
{
  "success": true,
  "total": 42,
  "limit": 20,
  "returned": 20,
  "messages": [
    {
      "id": 1,
      "username": "john_doe",
      "message": "Check this link: https://example.com",
      "timestamp": "2026-04-27 14:30:45",
      "received_at": 1704897045
    },
    ...
  ]
}
```

---

## 💾 Data Storage Format

**File Location:** `/data/honeypot_messages.json`

**Example Content:**
```json
[
  {
    "id": 1,
    "username": "john_doe",
    "message": "Please verify your account by clicking this link",
    "detected_keywords": ["verify", "click"],
    "keyword_count": 2,
    "timestamp": "2026-04-27 14:30:45",
    "received_at": 1704897045
  },
  {
    "id": 2,
    "username": "@suspicious",
    "message": "Claim your FREE reward! Login now for password recovery",
    "detected_keywords": ["claim", "free", "login", "password"],
    "keyword_count": 4,
    "timestamp": "2026-04-27 14:35:22",
    "received_at": 1704897322
  }
]
```

---

## 🔐 Validation & Security

### Input Validation
| Field | Min | Max | Rules |
|-------|-----|-----|-------|
| username | 2 | 50 | Length check, trim whitespace |
| message | 5 | 5000 | Length check, trim whitespace |

### Security Features
✅ Input validation (length checks)
✅ Keyword detection (8 suspicious keywords)
✅ Type declarations (strict_types)
✅ JSON encoding (safe storage)
✅ File permissions (0755)
✅ Error handling (try-catch)
✅ CORS headers (cross-origin safe)
✅ HTTP status codes (proper semantics)

---

## 💻 Usage Examples

### JavaScript/Fetch
```javascript
// Submit message
async function sendMessage(username, message) {
  const response = await fetch('/api/honeypot/submit.php', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: username,
      message: message
    })
  });
  
  const result = await response.json();
  // {success: true, message: "...", data: {..., detected_keywords: [...], keyword_count: N}}
  if (result.success) {
    console.log('Keywords detected:', result.data.detected_keywords);
    console.log('Count:', result.data.keyword_count);
  }
}

// Get messages
async function getMessages(limit = 20) {
  const response = await fetch(`/api/honeypot/messages.php?limit=${limit}`);
  const result = await response.json();
  console.log(`Total: ${result.total}, Returned: ${result.returned}`);
  // Each message includes detected_keywords and keyword_count
  result.messages.forEach(msg => {
    console.log(msg.username, '→', msg.detected_keywords);
  });
}
```

### cURL
```bash
# Submit
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test","message":"Test message"}'

# Get
curl "http://localhost/socialshield/api/honeypot/messages.php?limit=10"
```

### PHP
```php
// Include storage class
require_once 'api/honeypot/HoneypotJsonStorage.php';

// Initialize
$storage = new HoneypotJsonStorage('/path/to/data');

// Add message (automatically detects keywords)
$result = $storage->addMessage('user@example.com', 'Verify your account and claim your free reward');
// Returns: {success: true, data: {..., detected_keywords: ["verify", "claim", "free"], keyword_count: 3}}

if ($result['success']) {
  echo 'Found ' . $result['data']['keyword_count'] . ' keywords: ' . 
       implode(', ', $result['data']['detected_keywords']);
}

// Get all keywords being monitored
$keywords = $storage->getSuspiciousKeywords();
// Returns: ["verify", "login", "urgent", "free", "click", "claim", "reward", "password"]

// Manually detect keywords
$detected = $storage->detectKeywords('Click here');
// Returns: ["click"]

// Get recent messages (with keyword info)
$messages = $storage->getRecentMessages(20);
foreach ($messages as $msg) {
  echo $msg['username'] . ' → Keywords: ' . implode(', ', $msg['detected_keywords'] ?? []);
}

$count = $storage->getMessageCount();
```

---

## 📁 File Structure

```
SocialShield/
├── api/
│   └── honeypot/
│       ├── submit.php ⭐ NEW
│       ├── messages.php ⭐ NEW
│       └── HoneypotJsonStorage.php ⭐ NEW
│
├── admin/
│   └── honeypot_json.php ⭐ NEW
│
├── data/
│   └── honeypot_messages.json ⭐ AUTO-CREATED
│
├── api-test.php ⭐ NEW
├── API_DOCUMENTATION.md ⭐ NEW
└── ...
```

---

## 🧪 Testing

### Access Points

**API Testing Console:**
```
http://localhost/socialshield/api-test.php
```

**JSON Admin View:**
```
http://localhost/socialshield/admin/honeypot_json.php
```

**Direct API Calls:**
```
POST: http://localhost/socialshield/api/honeypot/submit.php
GET: http://localhost/socialshield/api/honeypot/messages.php
```

---

## 📊 HoneypotJsonStorage Class

### Public Methods

```php
// Initialize storage
$storage = new HoneypotJsonStorage($dataDir);

// Add message (returns array with success/error)
$result = $storage->addMessage($username, $message);

// Get all messages
$all = $storage->getAllMessages();

// Get recent messages (with limit)
$recent = $storage->getRecentMessages($limit = 20);

// Get total count
$count = $storage->getMessageCount();

// Get storage file path
$path = $storage->getStoragePath();

// Clear all messages (admin)
$storage->clearAll();
```

---

## ✅ What Was Delivered

✅ **Receives messages from frontend**
- POST endpoint for submissions
- Validates input (length, type)

✅ **Stores data with timestamp**
- JSON file storage
- Auto-generated ID
- ISO timestamp format
- Unix timestamp (received_at)

✅ **Returns success responses**
- 201 Created on success
- 400 Bad Request on validation error
- 500 Server Error on system failure

✅ **Simple & beginner-friendly**
- No database required
- Human-readable JSON format
- Clear API documentation
- Interactive testing console

✅ **No existing code modified**
- New API module isolated
- New storage class independent
- New admin view separate
- Backward compatible

---

## 🎯 Comparison: Database vs JSON Storage

| Feature | Database | JSON File |
|---------|----------|-----------|
| Setup | Requires MySQL | No setup needed |
| Query Speed | Fast | Slower |
| Large Data | Efficient | Less efficient |
| Learning | Complex | Simple |
| Portability | Requires DB | Just copy file |
| Backup | SQL dump | Copy JSON |
| Concurrent Access | Safe | Not recommended |

---

## 🚀 Next Steps

1. **Test Submission:**
   ```
   Visit /honeypot.php
   Fill form
   Click submit
   Check /admin/honeypot_json.php
   ```

2. **Test API Directly:**
   ```
   Visit /api-test.php
   Use console to send/retrieve
   View responses
   ```

3. **Monitor Messages:**
   ```
   Admin: /admin/honeypot_json.php
   View: /api/honeypot/messages.php?limit=20
   ```

---

## 📝 Compliance

✔️ Backend module created
✔️ Stores username, message, timestamp
✔️ JSON file storage (alternative to DB)
✔️ Success responses implemented
✔️ No existing code modified
✔️ Fully functional and tested

---

## 🔗 Quick Links

- **API Documentation:** `/API_DOCUMENTATION.md`
- **Testing Console:** `/api-test.php`
- **JSON Admin View:** `/admin/honeypot_json.php`
- **Public Form:** `/honeypot.php`
- **Database Admin:** `/admin/honeypot.php`

---

**Status:** ✅ Complete  
**Date:** April 27, 2026  
**Compatibility:** PHP 7.4+
