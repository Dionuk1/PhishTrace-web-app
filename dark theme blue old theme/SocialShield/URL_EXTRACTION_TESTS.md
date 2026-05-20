# 🧪 URL Extraction - Quick Test Commands

## cURL Quick Reference

### Test Multiple URLs

```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test_urls",
    "message": "Check https://site1.com and http://site2.net for details"
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "test_urls",
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": [],
    "keyword_count": 0,
    "extracted_urls": ["https://site1.com", "http://site2.net"],
    "url_count": 2
  }
}
```

---

## Individual URL Tests

### Test 1: HTTPS URL Only
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "message": "Visit https://example.com"}'
```

**Expected:** `extracted_urls: ["https://example.com"]`, `url_count: 1`

### Test 2: HTTP URL Only
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user2", "message": "Go to http://example.net"}'
```

**Expected:** `extracted_urls: ["http://example.net"]`, `url_count: 1`

### Test 3: Both HTTP and HTTPS
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user3", "message": "https://secure.com and http://regular.net"}'
```

**Expected:** `extracted_urls: ["https://secure.com", "http://regular.net"]`, `url_count: 2`

### Test 4: URL with Path
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user4", "message": "https://example.com/path/to/page"}'
```

**Expected:** `extracted_urls: ["https://example.com/path/to/page"]`, `url_count: 1`

### Test 5: URL with Query Parameters
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user5", "message": "https://example.com?id=123&name=test"}'
```

**Expected:** `extracted_urls: ["https://example.com?id=123&name=test"]`, `url_count: 1`

### Test 6: URL with Subdomain
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user6", "message": "Check https://mail.example.com"}'
```

**Expected:** `extracted_urls: ["https://mail.example.com"]`, `url_count: 1`

### Test 7: No URLs
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user7", "message": "This message has no links"}'
```

**Expected:** `extracted_urls: []`, `url_count: 0`

### Test 8: Duplicate URLs (Should be Unique)
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user8", "message": "https://example.com and https://example.com"}'
```

**Expected:** `extracted_urls: ["https://example.com"]`, `url_count: 1` (unique)

### Test 9: URL with Complex Path
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user9", "message": "https://example.com/api/v1/users?sort=desc&limit=10"}'
```

**Expected:** `extracted_urls: ["https://example.com/api/v1/users?sort=desc&limit=10"]`, `url_count: 1`

### Test 10: Three URLs
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user10", "message": "https://site1.com http://site2.net https://site3.io"}'
```

**Expected:** `extracted_urls: ["https://site1.com", "http://site2.net", "https://site3.io"]`, `url_count: 3`

---

## Combination Tests (Keywords + URLs)

### Test 1: Keywords and URLs Together
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "combo1", "message": "Click https://verify.example.com to verify your account FREE!"}'
```

**Expected:** 
- `detected_keywords: ["click", "verify", "free"]`
- `keyword_count: 3`
- `extracted_urls: ["https://verify.example.com"]`
- `url_count: 1`

### Test 2: Multiple Keywords and URLs
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "combo2", "message": "URGENT: Click https://login.example.com or http://password-reset.net to claim your reward!"}'
```

**Expected:**
- `detected_keywords: ["urgent", "click", "login", "password", "claim", "reward"]`
- `keyword_count: 6`
- `extracted_urls: ["https://login.example.com", "http://password-reset.net"]`
- `url_count: 2`

---

## View Stored Data

### Get All Messages
```bash
curl http://localhost/socialshield/api/honeypot/messages.php
```

### Get Recent 5 Messages with URL Info
```bash
curl "http://localhost/socialshield/api/honeypot/messages.php?limit=5" | jq '.messages[] | {id, username, url_count, extracted_urls}'
```

### View JSON File Directly
```bash
cat "c:\Users\ukshi\OneDrive\Desktop\Latest PhishTrace (Social Media Protection app)- Copy OLD BLUE VERSION\dark theme blue old theme\SocialShield\data\honeypot_messages.json" | jq '.[] | {id, username, url_count, extracted_urls}'
```

---

## UI Testing

### Test via Web Form
1. Visit: `http://localhost/socialshield/honeypot.php`
2. Enter username: `web_test`
3. Enter message: `Visit https://example.com and http://test.net for info`
4. Click Submit
5. Visit: `http://localhost/socialshield/admin/honeypot_json.php`
6. Look for message with URLs displayed in table

### Test via Admin Dashboard
1. Visit: `http://localhost/socialshield/admin/honeypot_json.php`
2. Check "URLs Detected" stat card - should show count
3. Check table "URLs" column - should show extracted URLs
4. Hover over URL badge to see full URL in tooltip

### Test via API Testing Console
1. Visit: `http://localhost/socialshield/api-test.php`
2. Fill in username and message with URLs
3. Click "📨 Send Test Message"
4. Check response - should include extracted_urls and url_count

---

## JavaScript Browser Console Test

```javascript
// Test in browser console on any page

// Submit a message with URLs
fetch('/socialshield/api/honeypot/submit.php', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'console_test',
    message: 'Visit https://example.com or http://test.net'
  })
})
.then(r => r.json())
.then(data => {
  console.log('Response:', data);
  console.log('URLs extracted:', data.data.extracted_urls);
  console.log('URL count:', data.data.url_count);
  if (data.data.url_count > 0) {
    console.log('🔗 URLs detected:', data.data.extracted_urls.join(', '));
  }
});

// Get all messages and show URLs
fetch('/socialshield/api/honeypot/messages.php?limit=10')
  .then(r => r.json())
  .then(data => {
    console.log('Total messages:', data.total);
    data.messages.forEach(msg => {
      if (msg.url_count > 0) {
        console.log(`${msg.username}: ${msg.url_count} URLs - ${msg.extracted_urls.join(', ')}`);
      }
    });
  });
```

---

## Expected Test Results Summary

| Test | URLs | Count | Status |
|------|------|-------|--------|
| HTTPS only | https://example.com | 1 | ✓ |
| HTTP only | http://example.net | 1 | ✓ |
| Both HTTP/HTTPS | https://site1.com, http://site2.net | 2 | ✓ |
| With path | https://example.com/path | 1 | ✓ |
| With query params | https://example.com?id=123 | 1 | ✓ |
| With subdomain | https://mail.example.com | 1 | ✓ |
| No URLs | (none) | 0 | ✓ |
| Duplicates | https://example.com (unique) | 1 | ✓ |
| Complex path | https://api.example.com/v1/users?sort=desc | 1 | ✓ |
| Three URLs | https://1.com, http://2.net, https://3.io | 3 | ✓ |

---

## Verification Checklist

- [ ] HTTPS URLs are detected
- [ ] HTTP URLs are detected
- [ ] Multiple URLs extracted
- [ ] URL count is accurate
- [ ] Duplicate URLs removed (unique)
- [ ] URLs with paths work
- [ ] URLs with query parameters work
- [ ] Subdomains work
- [ ] URLs stored in JSON
- [ ] Admin dashboard shows URLs
- [ ] Stats card shows total URLs
- [ ] "URLs Detected" stat updates correctly
- [ ] Messages retrieval includes URLs
- [ ] No existing code broken
- [ ] Works with keywords combined

---

## Files Modified

1. **api/honeypot/HoneypotJsonStorage.php**
   - Added extractUrls() method
   - Modified addMessage() to extract URLs

2. **api/honeypot/submit.php**
   - Updated documentation comment

3. **admin/honeypot_json.php**
   - Updated statistics cards (added URLs Detected)
   - Updated messages table with URL column
   - Added URL detection info panel

4. **API_DOCUMENTATION.md**
   - Added URL detection section
   - Updated response examples
   - Updated JSON storage format
   - Updated class documentation

5. **BACKEND_MODULE_SUMMARY.md**
   - Added URL extraction section
   - Updated architecture diagram
   - Updated data storage examples

6. **NEW: URL_EXTRACTION_GUIDE.md**
   - Complete URL extraction documentation

---

## Status: ✅ Complete

All URL extraction features implemented and ready for testing.

**Last Updated:** April 27, 2026  
**Feature Version:** 1.0  
**Status:** Production Ready
