# 🔗 URL Extraction - Test & Documentation

## Overview

The honeypot backend now includes **automatic URL extraction** that detects HTTP and HTTPS links from messages and stores them for analysis.

**Supported Protocols:**
```
http://, https://
```

---

## ✅ Feature Checklist

✅ **Detection Method:** Regex pattern matching (case-insensitive)  
✅ **Protocols:** http:// and https://  
✅ **Return Type:** Array of extracted URLs + count  
✅ **Storage:** URLs saved in JSON with each message  
✅ **Response:** Included in API response on submission  
✅ **Admin View:** Displayed in admin dashboard with badges  
✅ **No Existing Code Modified:** Completely new feature  

---

## 📊 How It Works

### Step 1: Message Submission
```
User submits: "Click https://example.com or visit http://phishing.net now!"
```

### Step 2: URL Extraction
```
System scans using regex pattern:
  #https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i

URLs found:
- https://example.com → FOUND ✓
- http://phishing.net → FOUND ✓
```

### Step 3: Return Results
```json
{
  "extracted_urls": ["https://example.com", "http://phishing.net"],
  "url_count": 2
}
```

### Step 4: Store in JSON
```json
{
  "id": 1,
  "username": "john_doe",
  "message": "Click https://example.com or visit http://phishing.net now!",
  "extracted_urls": ["https://example.com", "http://phishing.net"],
  "url_count": 2,
  "timestamp": "2026-04-27 14:30:45",
  "received_at": 1704897045
}
```

---

## 🔌 API Response Examples

### Example 1: Multiple URLs Detected

**Request:**
```json
{
  "username": "user1",
  "message": "Verify at https://secure.example.com and confirm at http://verify.test.net"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "user1",
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": ["verify"],
    "keyword_count": 1,
    "extracted_urls": ["https://secure.example.com", "http://verify.test.net"],
    "url_count": 2
  }
}
```

### Example 2: No URLs

**Request:**
```json
{
  "username": "user2",
  "message": "This message has no links or URLs in it"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 2,
    "username": "user2",
    "timestamp": "2026-04-27 14:30:46",
    "detected_keywords": [],
    "keyword_count": 0,
    "extracted_urls": [],
    "url_count": 0
  }
}
```

### Example 3: Mixed Content

**Request:**
```json
{
  "username": "user3",
  "message": "Urgent: Click https://verify.urgent.com to claim your free reward at http://rewards.test.net NOW!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 3,
    "username": "user3",
    "timestamp": "2026-04-27 14:30:47",
    "detected_keywords": ["urgent", "click", "free"],
    "keyword_count": 3,
    "extracted_urls": ["https://verify.urgent.com", "http://rewards.test.net"],
    "url_count": 2
  }
}
```

---

## 🧪 Testing Scenarios

### Test 1: Simple HTTPS URL
**Message:** `Visit https://example.com`  
**Expected URLs:** `["https://example.com"]`  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test1","message":"Visit https://example.com"}'
```

### Test 2: Simple HTTP URL
**Message:** `Go to http://example.net`  
**Expected URLs:** `["http://example.net"]`  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test2","message":"Go to http://example.net"}'
```

### Test 3: Multiple URLs (HTTP and HTTPS)
**Message:** `Check https://site1.com and http://site2.net`  
**Expected URLs:** `["https://site1.com", "http://site2.net"]`  
**Expected Count:** 2  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test3","message":"Check https://site1.com and http://site2.net"}'
```

### Test 4: URLs with Query Parameters
**Message:** `https://example.com?id=123&name=test`  
**Expected URLs:** `["https://example.com?id=123&name=test"]`  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test4","message":"https://example.com?id=123&name=test"}'
```

### Test 5: URLs with Paths
**Message:** `Visit https://example.com/path/to/page`  
**Expected URLs:** `["https://example.com/path/to/page"]`  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test5","message":"Visit https://example.com/path/to/page"}'
```

### Test 6: No URLs
**Message:** `This is a normal message with no URLs`  
**Expected URLs:** `[]`  
**Expected Count:** 0  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test6","message":"This is a normal message with no URLs"}'
```

### Test 7: Duplicate URLs (Should be Unique)
**Message:** `https://example.com and https://example.com again`  
**Expected URLs:** `["https://example.com"]` (unique)  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test7","message":"https://example.com and https://example.com again"}'
```

### Test 8: URL with Special Characters
**Message:** `https://example.com/page#section?id=1&name=test`  
**Expected URLs:** `["https://example.com/page#section?id=1&name=test"]`  
**Expected Count:** 1  

**cURL:**
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"test8","message":"https://example.com/page#section?id=1&name=test"}'
```

---

## 💻 Code Integration

### In HoneypotJsonStorage Class

**Extract URLs:**
```php
$storage = new HoneypotJsonStorage('/path/to/data');

// Method 1: Automatic extraction (called by addMessage)
$result = $storage->addMessage('user', 'Visit https://example.com');
echo $result['data']['url_count'];  // Output: 1
echo implode(', ', $result['data']['extracted_urls']);  // Output: https://example.com

// Method 2: Manual extraction
$urls = $storage->extractUrls('Check https://example.com and http://test.net');
// Returns: ["https://example.com", "http://test.net"]
```

### In JavaScript

```javascript
async function submitWithUrlCheck(username, message) {
  const response = await fetch('/api/honeypot/submit.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, message})
  });

  const result = await response.json();
  
  if (result.success) {
    const urls = result.data.extracted_urls;
    const count = result.data.url_count;
    
    if (count > 0) {
      console.log(`🔗 Found ${count} URL(s): ${urls.join(', ')}`);
      // Show warning to admin with URLs
      showUrlWarning(urls);
    } else {
      console.log('✓ No URLs detected');
    }
  }
}
```

---

## 📊 Admin Dashboard Display

**JSON Admin View:** `/admin/honeypot_json.php`

The admin dashboard displays:
- **Statistics:** "URLs Detected" card shows total URL count across all messages
- **Table Columns:**
  - URLs (with truncated display and link count)
  - Shows first URL with tooltip for full URL
  - Shows "+N" for additional URLs
- **URL Detection Panel:** Explains how URL extraction works

**URL Display:**
- **Info Badge** (`bg-info`): URL display with 🔗 emoji
- **Secondary Badge** (`bg-secondary`): Additional URL count
- **Truncation:** Shows first 25 chars of URL with "..."
- **Tooltip:** Full URL visible on hover

---

## 🔍 Extraction Algorithm

```php
public function extractUrls(string $message): array
{
    $urls = [];
    
    // Regex pattern to match http and https URLs
    $pattern = '#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i';
    
    if (preg_match_all($pattern, $message, $matches)) {
        $urls = array_unique($matches[0]);  // Remove duplicates
        $urls = array_values($urls);         // Re-index array
    }
    
    return $urls;
}
```

**Regex Breakdown:**
- `https?://` - Matches http:// or https://
- `[^\s<>"{}|\\^`\[\]]*` - Matches any character except whitespace, HTML brackets, etc.
- `[a-zA-Z0-9/]` - Must end with alphanumeric or slash
- `#i` - Case-insensitive flag

---

## 📈 Use Cases

### Case 1: Phishing Detection
```
Message: "Verify account: https://paypal-verify.phishing.com"
URLs Extracted: ["https://paypal-verify.phishing.com"]
Admin Alert: 🔗 URL detected - check domain for phishing
```

### Case 2: Malware Distribution
```
Message: "Download file from http://malware-site.ru/trojan.exe"
URLs Extracted: ["http://malware-site.ru/trojan.exe"]
Admin Alert: 🔗 URL detected - scan for malware
```

### Case 3: Legitimate URL Reference
```
Message: "Learn more at https://wikipedia.org/wiki/cybersecurity"
URLs Extracted: ["https://wikipedia.org/wiki/cybersecurity"]
Admin Alert: ℹ️ URL detected - may be educational
```

### Case 4: Multiple Redirects
```
Message: "Get reward: https://redir1.com then https://redir2.com then http://final-phish.net"
URLs Extracted: ["https://redir1.com", "https://redir2.com", "http://final-phish.net"]
Admin Alert: 🔗 Multiple URLs detected - possible redirect chain
```

---

## 🔧 URL Pattern Details

**Protocols Supported:**
- ✅ `http://` - Unencrypted HTTP
- ✅ `https://` - Secure HTTPS

**URL Components Captured:**
- ✅ Domain names (example.com, mail.google.com, etc.)
- ✅ Subdomains (sub.example.com)
- ✅ Paths (/path/to/page)
- ✅ Query parameters (?id=123&name=test)
- ✅ Fragments (#section)
- ✅ Port numbers (:8080, :443, etc.)

**URL Boundaries:**
- ❌ Not captured: Text before http/https
- ❌ Not captured: Angle brackets < and >
- ✅ Captured: URLs followed by punctuation (mostly)
- ✅ Captured: URLs at end of message

---

## 📝 API Reference

### HoneypotJsonStorage::extractUrls()

```php
/**
 * Extract URLs from message (http and https)
 * 
 * @param string $message The message text to scan
 * @return array Array of extracted URLs (unique, re-indexed)
 */
public function extractUrls(string $message): array
```

**Parameters:**
- `$message` (string, required) - Message text to scan

**Returns:**
- Array of extracted URLs (empty array if none found)
- URLs are unique (no duplicates)
- Array is re-indexed (0-based keys)

**Examples:**
```php
$storage->extractUrls('Visit https://example.com');
// Returns: ["https://example.com"]

$storage->extractUrls('Check https://site1.com and http://site2.net');
// Returns: ["https://site1.com", "http://site2.net"]

$storage->extractUrls('https://example.com https://example.com');
// Returns: ["https://example.com"] (unique)

$storage->extractUrls('No URLs here');
// Returns: []
```

---

## ✅ Compliance

✔️ Requirement: Detect http and https links  
✔️ Requirement: Return list of URLs found  
✔️ Requirement: Return empty array if none found  
✔️ Requirement: No existing code modified  
✔️ Requirement: Automatic URL extraction in API  
✔️ Requirement: Admin dashboard displays URLs  
✔️ Requirement: URLs stored in JSON  

---

## 🎯 Implementation Summary

| Component | Status | Location |
|-----------|--------|----------|
| URL Extraction | ✅ Complete | HoneypotJsonStorage::extractUrls() |
| Auto-Extraction | ✅ Complete | HoneypotJsonStorage::addMessage() |
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
**Feature:** URL Extraction v1.0
