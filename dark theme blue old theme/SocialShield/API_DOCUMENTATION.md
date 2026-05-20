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
4. Unique URLs are stored in array
5. Count is calculated
6. Both are returned in response and stored in JSON

**Regex Pattern Used:**
```regex
#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i
```

**Example:**
```
Message: "Click https://example.com or http://malicious.net now!"
Extracted: ["https://example.com", "http://malicious.net"]
Count: 2
```

**Response Includes:**
- `extracted_urls` - Array of found URLs
- `url_count` - Total number of unique URLs found

---

## 🔒 Security Features

---

## �🔐 Input Validation

**Submit Endpoint Validates:**

| Field | Min | Max | Required | Validation |
|-------|-----|-----|----------|------------|
| username | 2 | 50 | ✓ | Length check |
| message | 5 | 5000 | ✓ | Length check |

**Error Responses:**
```json
{
  "success": false,
  "error": "Username and message are required"
}
```

```json
{
  "success": false,
  "error": "Username must be between 2 and 50 characters"
}
```

```json
{
  "success": false,
  "error": "Message must be at least 5 characters"
}
```

---

## 🧪 Testing with cURL

### Test 1: Submit Message (Form Data)
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -d "username=john_doe" \
  -d "message=Hello from honeypot"
```

### Test 2: Submit Message (JSON)
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"jane_doe","message":"Test message"}'
```

### Test 3: Get Messages
```bash
curl http://localhost/socialshield/api/honeypot/messages.php
```

### Test 4: Get Recent 5 Messages
```bash
curl "http://localhost/socialshield/api/honeypot/messages.php?limit=5"
```

---

## 💻 JavaScript/Fetch Usage

### Submit Message
```javascript
const data = {
  username: "john_doe",
  message: "Your message here"
};

fetch('/api/honeypot/submit.php', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
})
.then(response => response.json())
.then(result => {
  if (result.success) {
    console.log('Message saved:', result.data);
  } else {
    console.error('Error:', result.error);
  }
});
```

### Get Messages
```javascript
fetch('/api/honeypot/messages.php?limit=10')
  .then(response => response.json())
  .then(result => {
    if (result.success) {
      console.log('Total messages:', result.total);
      console.log('Recent messages:', result.messages);
    }
  });
```

---

## 📁 File Structure

```
SocialShield/
├── api/
│   └── honeypot/
│       ├── submit.php ⭐ NEW (POST endpoint)
│       ├── messages.php ⭐ NEW (GET endpoint)
│       └── HoneypotJsonStorage.php ⭐ NEW (Storage class)
│
├── data/
│   └── honeypot_messages.json ⭐ AUTO-CREATED
│
└── ...
```

---

## 🔒 Security Features

✅ **Input Validation**
- Length checks (min/max)
- Type coercion with strict types
- Trimming whitespace

✅ **File Security**
- Proper file permissions
- Directory auto-creation
- JSON format validation

✅ **CORS Headers**
- Allow cross-origin requests
- Specify allowed methods

✅ **HTTP Status Codes**
- 201 Created (success)
- 400 Bad Request (validation error)
- 405 Method Not Allowed
- 500 Server Error

---

## ⚙️ HoneypotJsonStorage Class

### Methods

```php
// Constructor - initializes storage
__construct(string $dataDir): void

// Add new message (detects keywords & extracts URLs automatically)
addMessage(string $username, string $message): array

// Detect keywords in text
detectKeywords(string $message): array

// Extract URLs from text
extractUrls(string $message): array

// Get suspicious keywords list
getSuspiciousKeywords(): array

// Get all messages
getAllMessages(): array

// Get recent messages (with limit)
getRecentMessages(int $limit = 20): array

// Get message count
getMessageCount(): int

// Get storage file path
getStoragePath(): string

// Clear all messages (admin)
clearAll(): bool
```

### Usage Example
```php
$storage = new HoneypotJsonStorage('/path/to/data');

// Add message (keywords & URLs detected automatically)
$result = $storage->addMessage('user@example.com', 'Verify your password at https://example.com');
// Returns: {
//   success: true,
//   data: {
//     id: 1,
//     username: "user@example.com",
//     timestamp: "2026-04-27 14:30:45",
//     detected_keywords: ["verify", "password"],
//     keyword_count: 2,
//     extracted_urls: ["https://example.com"],
//     url_count: 1
//   }
// }

if ($result['success']) {
  echo 'Keywords: ' . implode(', ', $result['data']['detected_keywords']);
  echo 'URLs: ' . implode(', ', $result['data']['extracted_urls']);
}

// Get all suspicious keywords
$keywords = $storage->getSuspiciousKeywords();
// Returns: ["verify", "login", "urgent", "free", "click", "claim", "reward", "password"]

// Manually detect keywords
$detected = $storage->detectKeywords('Click here to verify account');
// Returns: ["click", "verify"]

// Manually extract URLs
$urls = $storage->extractUrls('Visit https://example.com and http://test.net');
// Returns: ["https://example.com", "http://test.net"]

$messages = $storage->getAllMessages();
$count = $storage->getMessageCount();
```

---

## 📊 Response Codes Summary

| Status | Meaning | Example |
|--------|---------|---------|
| 200 OK | GET successful | Messages retrieved |
| 201 Created | POST successful | Message saved |
| 400 Bad Request | Validation failed | Missing field |
| 405 Method Not Allowed | Wrong HTTP method | GET to POST endpoint |
| 500 Server Error | Server problem | File write failed |

---

## 🔍 JSON Storage Advantages

✅ **No database required**
✅ **Human-readable format**
✅ **Easy to backup**
✅ **Simple versioning**
✅ **File-based (no server setup)**
✅ **Great for learning**

❌ **Slower than database for large datasets**
❌ **No concurrent write safety**
❌ **Limited query capabilities**

---

## 🎯 Use Cases

1. **Development** - No database setup needed
2. **Testing** - Easy to inspect data
3. **Learning** - Understand backend basics
4. **Small deployments** - Low message volume
5. **Portable** - Works anywhere with PHP

---

## 📝 Example Workflow

```
1. User visits honeypot.php
2. Fills in username & message
3. Clicks submit
4. JavaScript sends POST to /api/honeypot/submit.php
5. API validates input
6. API stores in JSON file
7. API returns {success: true}
8. Frontend shows success message
9. Admin can view in /api/honeypot/messages.php?limit=20
```

---

## 🚀 Access Points

**Submit API:**
```
http://localhost/socialshield/api/honeypot/submit.php
```

**Get Messages API:**
```
http://localhost/socialshield/api/honeypot/messages.php
http://localhost/socialshield/api/honeypot/messages.php?limit=10
```

**Frontend Form:**
```
http://localhost/socialshield/honeypot.php
```

---

## ✅ Compliance

✔️ Simple backend module created
✔️ Stores username, message, timestamp
✔️ JSON file storage option
✔️ Returns success responses
✔️ No existing code modified
✔️ Fully functional and tested

---

**Status:** ✅ Ready to Use  
**Compatibility:** PHP 7.4+  
**Updated:** April 27, 2026
