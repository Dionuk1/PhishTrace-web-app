# 🧪 Keyword Detection - Quick Test Commands

## cURL Quick Reference

### Test All 8 Keywords in One Message

```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test_all_keywords",
    "message": "Please verify your login. Urgent offer: FREE claim and reward! Password click here!"
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "test_all_keywords",
    "timestamp": "2026-04-27 14:30:45",
    "detected_keywords": ["verify", "login", "urgent", "free", "claim", "reward", "password", "click"],
    "keyword_count": 8
  }
}
```

---

## Individual Keyword Tests

### Test 1: "verify" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "message": "Please verify your account"}'
```

### Test 2: "login" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user2", "message": "Login to your account now"}'
```

### Test 3: "urgent" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user3", "message": "Urgent action required immediately"}'
```

### Test 4: "free" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user4", "message": "Get your free prize today"}'
```

### Test 5: "click" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user5", "message": "Click here to continue"}'
```

### Test 6: "claim" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user6", "message": "Claim your winnings now"}'
```

### Test 7: "reward" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user7", "message": "Your reward is waiting"}'
```

### Test 8: "password" keyword
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "user8", "message": "Update your password"}'
```

---

## Edge Cases

### Case-Insensitive Test
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "case_test", "message": "VERIFY YOUR PASSWORD"}'
```
**Expected:** Should detect both "verify" and "password" regardless of case

### Substring Matching Test
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "substring_test", "message": "verification process and clicking the link"}'
```
**Expected:** Should detect "verify" in "verification" and "click" in "clicking"

### No Keywords Test
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "normal_user", "message": "This is just a normal message with no suspicious content here"}'
```
**Expected:** Empty detected_keywords array and keyword_count = 0

### Duplicate Keywords Test
```bash
curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username": "dup_test", "message": "verify verify verify click click"}'
```
**Expected:** Should return unique keywords: ["verify", "click"] with count = 2

---

## View Stored Data

### Get All Messages
```bash
curl http://localhost/socialshield/api/honeypot/messages.php
```

### Get Recent 5 Messages
```bash
curl "http://localhost/socialshield/api/honeypot/messages.php?limit=5"
```

### View JSON File Directly
```bash
cat "c:\Users\ukshi\OneDrive\Desktop\Latest PhishTrace (Social Media Protection app)- Copy OLD BLUE VERSION\dark theme blue old theme\SocialShield\data\honeypot_messages.json"
```

---

## UI Testing

### Test via Web Form
1. Visit: `http://localhost/socialshield/honeypot.php`
2. Enter username: `web_test_user`
3. Enter message: `Click here to verify your free password reward urgently!`
4. Click Submit
5. Visit: `http://localhost/socialshield/admin/honeypot_json.php`
6. Look for the message with badges showing detected keywords

### Test via Admin Dashboard
1. Visit: `http://localhost/socialshield/admin/honeypot_json.php`
2. Check "Monitored Keywords" section - should list all 8 keywords
3. Check "With Keywords" stat card - should show count
4. View table - should show detected keywords in colored badges for each message

### Test via API Testing Console
1. Visit: `http://localhost/socialshield/api-test.php`
2. Fill in username and message
3. Click "📨 Send Test Message"
4. Check response - should include detected_keywords and keyword_count

---

## JavaScript Browser Console Test

```javascript
// Test in browser console on any page

// Submit a message with keywords
fetch('/socialshield/api/honeypot/submit.php', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'console_test',
    message: 'Click here to verify your free reward password'
  })
})
.then(r => r.json())
.then(data => {
  console.log('Response:', data);
  console.log('Keywords detected:', data.data.detected_keywords);
  console.log('Keyword count:', data.data.keyword_count);
  if (data.data.keyword_count > 0) {
    console.log('⚠️ Suspicious message detected!');
  }
});

// Get all messages
fetch('/socialshield/api/honeypot/messages.php?limit=10')
  .then(r => r.json())
  .then(data => {
    console.log('Total messages:', data.total);
    data.messages.forEach(msg => {
      console.log(`${msg.username}: ${msg.keyword_count} keywords - ${msg.detected_keywords.join(', ')}`);
    });
  });
```

---

## Expected Test Results Summary

| Test | Keywords | Count | Status |
|------|----------|-------|--------|
| All 8 keywords | verify, login, urgent, free, click, claim, reward, password | 8 | ✓ |
| Verify | verify | 1 | ✓ |
| Login | login | 1 | ✓ |
| Urgent | urgent | 1 | ✓ |
| Free | free | 1 | ✓ |
| Click | click | 1 | ✓ |
| Claim | claim | 1 | ✓ |
| Reward | reward | 1 | ✓ |
| Password | password | 1 | ✓ |
| Case-insensitive | VERIFY, CLICK | 2 | ✓ |
| Substring match | verification, clicking | 2 (verify, click) | ✓ |
| No keywords | (none) | 0 | ✓ |
| Duplicates | verify, verify, click, click | 2 (unique) | ✓ |

---

## Verification Checklist

- [ ] All 8 keywords are detected
- [ ] Keywords are returned in response
- [ ] Keyword count is accurate
- [ ] Keywords are stored in JSON
- [ ] Case-insensitive detection works
- [ ] Substring matching works
- [ ] Unique keywords returned (no duplicates)
- [ ] Admin dashboard shows keywords
- [ ] Monitored keywords panel visible
- [ ] "With Keywords" stat updates correctly
- [ ] Messages retrieval includes keywords
- [ ] No existing code broken

---

## Files Modified

1. **api/honeypot/HoneypotJsonStorage.php**
   - Added suspiciousKeywords property
   - Added detectKeywords() method
   - Added getSuspiciousKeywords() method
   - Modified addMessage() to detect keywords

2. **api/honeypot/submit.php**
   - Updated documentation comment

3. **admin/honeypot_json.php**
   - Updated statistics cards
   - Updated messages table with keyword columns
   - Added monitored keywords panel

4. **API_DOCUMENTATION.md**
   - Added keyword detection section
   - Updated response examples
   - Updated JSON storage format
   - Updated class documentation

5. **BACKEND_MODULE_SUMMARY.md**
   - Added keyword detection section
   - Updated architecture diagram
   - Updated data storage examples
   - Updated usage examples

6. **NEW: KEYWORD_DETECTION_GUIDE.md**
   - Complete keyword detection documentation

---

## Status: ✅ Complete

All keyword detection features implemented and ready for testing.

**Last Updated:** April 27, 2026  
**Feature Version:** 1.0  
**Status:** Production Ready
