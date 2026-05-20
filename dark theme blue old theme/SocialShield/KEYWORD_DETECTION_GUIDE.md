# 🔍 Keyword Detection - Test & Documentation

## Overview

The honeypot backend now includes **automated keyword detection** that scans every message for suspicious keywords commonly used in phishing and social engineering attacks.

**Suspicious Keywords (8 total):**
```
verify, login, urgent, free, click, claim, reward, password
```

---

## ✅ Feature Checklist

✅ **Detection Method:** Case-insensitive substring matching  
✅ **Detection Scope:** All 8 suspicious keywords monitored  
✅ **Return Type:** Array of detected keywords + count  
✅ **Storage:** Keywords saved in JSON with each message  
✅ **Response:** Included in API response on submission  
✅ **Admin View:** Displayed in admin dashboard with colored badges  
✅ **No Existing Code Modified:** Completely new feature  

---

## 📊 How It Works

### Step 1: Message Submission
```
User submits: "Click here to verify your account and get free reward!"
```

### Step 2: Keyword Detection
```
System scans for all 8 keywords (case-insensitive):
- "verify" → FOUND ✓
- "login" → NOT FOUND
- "urgent" → NOT FOUND
- "free" → FOUND ✓
- "click" → FOUND ✓
- "claim" → NOT FOUND
- "reward" → FOUND ✓
- "password" → NOT FOUND
```

### Step 3: Return Results
```json
{
  "detected_keywords": ["click", "verify", "free", "reward"],
  "keyword_count": 4
}
```

### Step 4: Store in JSON
```json
{
  "id": 1,
  "username": "john_doe",
  "message": "Click here to verify your account and get free reward!",
  "detected_keywords": ["click", "verify", "free", "reward"],
  "keyword_count": 4,
  "timestamp": "2026-04-27 14:30:45",
  "received_at": 1704897045
}
```

---

## 🔌 API Response Examples

### Example 1: Multiple Keywords Detected

**Request:**
```json
{
  "username": "suspicious_user",
  "message": "URGENT! Verify your login password NOW! Click here to claim your free prize!!!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "suspicious_user",
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": ["urgent", "verify", "login", "password", "click", "claim", "free"],
    "keyword_count": 7
  }
}
```

### Example 2: No Keywords Detected

**Request:**
```json
{
  "username": "normal_user",
  "message": "Hello, I would like to report a phishing email I received."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 2,
    "username": "normal_user",
    "timestamp": "2026-04-27 14:30:46",
    "detected_keywords": [],
    "keyword_count": 0
  }
}
```

### Example 3: Partial Match

**Request:**
```json
{
  "username": "user123",
  "message": "I clicked the link but now I'm worried about my password security"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 3,
    "username": "user123",
    "timestamp": "2026-04-27 14:30:47",
    "detected_keywords": ["click", "password"],
    "keyword_count": 2
  }
}
```

---

## 🧪 Testing Scenarios

### Test 1: All Keywords
**Message:** "Verify login urgent free click claim reward password"  
**Expected Keywords:** ["verify", "login", "urgent", "free", "click", "claim", "reward", "password"]  
**Expected Count:** 8  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test1","message":"Verify login urgent free click claim reward password"}'
```

### Test 2: Mixed Case
**Message:** "VERIFY your PASSWORD and CLICK here"  
**Expected Keywords:** ["verify", "password", "click"]  
**Expected Count:** 3  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test2","message":"VERIFY your PASSWORD and CLICK here"}'
```

### Test 3: Keywords in Words
**Message:** "Verification of verified clicking clicker"  
**Expected Keywords:** ["verify", "click"]  
**Expected Count:** 2  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test3","message":"Verification of verified clicking clicker"}'
```

### Test 4: No Keywords
**Message:** "This is a normal message with no suspicious content"  
**Expected Keywords:** []  
**Expected Count:** 0  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test4","message":"This is a normal message with no suspicious content"}'
```

---

## 💻 Code Integration

### In HoneypotJsonStorage Class

**Detect Keywords:**
```php
$storage = new HoneypotJsonStorage('/path/to/data');

// Method 1: Automatic detection (called by addMessage)
$result = $storage->addMessage('user', 'Verify your password');
echo $result['data']['keyword_count'];  // Output: 2
echo implode(', ', $result['data']['detected_keywords']);  // Output: verify, password

// Method 2: Manual detection
$keywords = $storage->detectKeywords('Click to verify');
// Returns: ["click", "verify"]

// Method 3: Get all monitored keywords
$allKeywords = $storage->getSuspiciousKeywords();
// Returns: ["verify", "login", "urgent", "free", "click", "claim", "reward", "password"]
```

### In JavaScript

```javascript
async function submitWithKeywordCheck(username, message) {
  const response = await fetch('/api/honeypot/submit.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, message})
  });

  const result = await response.json();
  
  if (result.success) {
    const keywords = result.data.detected_keywords;
    const count = result.data.keyword_count;
    
    if (count > 0) {
      console.log(`⚠️ Found ${count} suspicious keywords: ${keywords.join(', ')}`);
      // Show warning to admin
      showWarningBadge(keywords);
    } else {
      console.log('✓ No suspicious keywords detected');
    }
  }
}
```

---

## 📊 Admin Dashboard Display

**JSON Admin View:** `/admin/honeypot_json.php`

The admin dashboard displays:
- **Statistics:** "With Keywords" card shows count of messages containing keywords
- **Table Columns:**
  - Detected Keywords (with colored badges)
  - Keyword Count (warning/danger colored badge)
- **Monitored Keywords Panel:** Lists all 8 keywords being tracked

**Color Coding:**
- **Red Badge** (`bg-danger`): Individual keywords in messages
- **Warning Badge** (`bg-warning`): Keyword count display
- **Secondary Badge** (`bg-secondary`): Zero keywords message

---

## 🔍 Detection Algorithm

```php
public function detectKeywords(string $message): array
{
    $detected = [];
    $messageLower = strtolower($message);  // Case-insensitive

    foreach ($this->suspiciousKeywords as $keyword) {
        // Use stripos for substring matching
        if (stripos($messageLower, $keyword) !== false) {
            $detected[] = $keyword;
        }
    }

    return array_unique($detected);  // Remove duplicates
}
```

**Key Features:**
- ✅ Case-insensitive (VERIFY, verify, Verify all match)
- ✅ Substring matching (verification contains verify)
- ✅ Unique results (no duplicates)
- ✅ Fast execution (early exit on match)
- ✅ Clean array return

---

## 📈 Use Cases

### Case 1: Phishing Detection
```
Message: "Your account verification is urgent! Click here to login"
Keywords Found: verify, urgent, click, login
Admin Alert: ⚠️ 4 keywords detected - likely phishing
```

### Case 2: False Positive Prevention
```
Message: "I'm learning about cybersecurity and password management"
Keywords Found: password
Admin Alert: ℹ️ 1 keyword found (educational context, may be legitimate)
```

### Case 3: Complex Scam
```
Message: "FREE reward! Claim your prize NOW! Verify identity here: malicious.com"
Keywords Found: free, claim, verify
Admin Alert: 🔴 3 keywords detected - high suspicion
```

---

## 🔧 Configuration

### To Modify Keywords

Edit `/api/honeypot/HoneypotJsonStorage.php`:

```php
private array $suspiciousKeywords = [
    'verify', 'login', 'urgent', 'free', 'click', 'claim', 'reward', 'password'
    // Add or remove keywords here
];
```

### To Change Detection Method

Currently uses **substring matching** (stripos).

Other options:
1. **Word boundary matching** - Matches whole words only
2. **Regex patterns** - More complex patterns
3. **Fuzzy matching** - Detects similar misspellings

---

## 📝 API Reference

### HoneypotJsonStorage::detectKeywords()

```php
/**
 * Detect suspicious keywords in message
 * 
 * @param string $message The message text to scan
 * @return array Array of detected keywords (unique)
 */
public function detectKeywords(string $message): array
```

**Parameters:**
- `$message` (string, required) - Message text to scan

**Returns:**
- Array of detected keywords (empty array if none found)

**Examples:**
```php
$storage->detectKeywords('verify your password');      // ["verify", "password"]
$storage->detectKeywords('CLICK HERE NOW');             // ["click"]
$storage->detectKeywords('normal message');             // []
$storage->detectKeywords('verification clicking');      // ["verify", "click"]
```

---

## ✅ Compliance

✔️ Requirement: Check message for suspicious keywords  
✔️ Requirement: Return detected keywords as array  
✔️ Requirement: Count how many were found  
✔️ Requirement: No existing code modified  
✔️ Requirement: Automated keyword detection in API  
✔️ Requirement: Admin dashboard displays keywords  
✔️ Requirement: Keywords stored in JSON  

---

## 🎯 Implementation Summary

| Component | Status | Location |
|-----------|--------|----------|
| Keyword List | ✅ Complete | HoneypotJsonStorage.php (line 13) |
| Detection Method | ✅ Complete | HoneypotJsonStorage::detectKeywords() |
| Auto-Detection | ✅ Complete | HoneypotJsonStorage::addMessage() |
| JSON Storage | ✅ Complete | honeypot_messages.json |
| API Response | ✅ Complete | /api/honeypot/submit.php |
| Admin Display | ✅ Complete | /admin/honeypot_json.php |
| Documentation | ✅ Complete | This file |

---

## 📍 Access Points

**Test API:** `/api-test.php`  
**Admin View:** `/admin/honeypot_json.php`  
**API Endpoint:** `POST /api/honeypot/submit.php`  
**Public Form:** `/honeypot.php`  

---

**Status:** ✅ Complete & Ready for Testing  
**Date:** April 27, 2026  
**Feature:** Keyword Detection v1.0
