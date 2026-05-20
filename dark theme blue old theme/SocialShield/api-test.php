<?php
/**
 * API Testing & Demo Page
 * Quick reference for testing the honeypot API endpoints
 */

declare(strict_types=1);

$pageTitle = 'API Testing Console';
require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid py-4">
    <h2 class="h4 mb-4">🔬 API Testing Console</h2>

    <div class="row g-4">
        <!-- Documentation Column -->
        <div class="col-lg-6">
            <div class="card shadow-sm">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">📚 API Endpoints</h5>
                </div>
                <div class="card-body">
                    <h6 class="mt-3">1. Submit Message (POST)</h6>
                    <code class="d-block bg-light p-2 rounded mb-2 small">
                        POST /api/honeypot/submit.php
                    </code>
                    <p class="small text-muted">
                        Send a message to the honeypot. Returns success response.
                    </p>

                    <h6 class="mt-3">2. Get Messages (GET)</h6>
                    <code class="d-block bg-light p-2 rounded mb-2 small">
                        GET /api/honeypot/messages.php?limit=20
                    </code>
                    <p class="small text-muted">
                        Retrieve stored messages. Limit: 1-100 (default: 20).
                    </p>

                    <h6 class="mt-3">Request Body (JSON)</h6>
                    <pre class="bg-light p-2 rounded small"><code>{
  "username": "john_doe",
  "message": "Your message here"
}</code></pre>

                    <h6 class="mt-3">Success Response (201)</h6>
                    <pre class="bg-light p-2 rounded small"><code>{
  "success": true,
  "message": "Message saved successfully",
  "data": {
    "id": 1,
    "username": "john_doe",
    "timestamp": "2026-04-27 14:30:45"
  }
}</code></pre>
                </div>
            </div>
        </div>

        <!-- Testing Column -->
        <div class="col-lg-6">
            <div class="card shadow-sm">
                <div class="card-header bg-success text-white">
                    <h5 class="mb-0">✅ Quick Test</h5>
                </div>
                <div class="card-body">
                    <form id="testForm">
                        <div class="mb-3">
                            <label class="form-label fw-semibold">Username</label>
                            <input type="text" class="form-control" id="testUsername" placeholder="john_doe" value="test_user">
                        </div>

                        <div class="mb-3">
                            <label class="form-label fw-semibold">Message</label>
                            <textarea class="form-control" id="testMessage" rows="3" placeholder="Your test message">Test message from API console</textarea>
                        </div>

                        <button type="submit" class="btn btn-success w-100">📨 Send Test Message</button>
                    </form>

                    <hr>

                    <h6 class="mt-3">📊 Get Messages</h6>
                    <div class="mb-3">
                        <label class="form-label fw-semibold">Limit</label>
                        <input type="number" class="form-control" id="msgLimit" value="10" min="1" max="100">
                    </div>
                    <button class="btn btn-info w-100" id="getMessagesBtn">🔍 Fetch Messages</button>

                    <hr class="my-3">

                    <div id="responseContainer" style="display: none;">
                        <h6>Response:</h6>
                        <pre id="responseBody" class="bg-light p-2 rounded small" style="max-height: 300px; overflow-y: auto;"></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- cURL Examples -->
    <div class="row mt-4">
        <div class="col-12">
            <div class="card shadow-sm">
                <div class="card-header">
                    <h5 class="mb-0">📝 cURL Command Examples</h5>
                </div>
                <div class="card-body">
                    <h6>Submit Message (Form Data)</h6>
                    <pre class="bg-light p-3 rounded small"><code>curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -d "username=john_doe" \
  -d "message=Hello from API"</code></pre>

                    <h6 class="mt-3">Submit Message (JSON)</h6>
                    <pre class="bg-light p-3 rounded small"><code>curl -X POST http://localhost/socialshield/api/honeypot/submit.php \
  -H "Content-Type: application/json" \
  -d '{"username":"jane_doe","message":"Test message"}'</code></pre>

                    <h6 class="mt-3">Get All Messages</h6>
                    <pre class="bg-light p-3 rounded small"><code>curl http://localhost/socialshield/api/honeypot/messages.php</code></pre>

                    <h6 class="mt-3">Get Recent 5 Messages</h6>
                    <pre class="bg-light p-3 rounded small"><code>curl "http://localhost/socialshield/api/honeypot/messages.php?limit=5"</code></pre>
                </div>
            </div>
        </div>
    </div>

    <!-- File Paths -->
    <div class="row mt-4">
        <div class="col-12">
            <div class="card shadow-sm border-info">
                <div class="card-header bg-info text-white">
                    <h5 class="mb-0">📂 Storage & File Information</h5>
                </div>
                <div class="card-body">
                    <table class="table table-sm">
                        <tr>
                            <td><strong>Messages JSON File:</strong></td>
                            <td><code>/data/honeypot_messages.json</code></td>
                        </tr>
                        <tr>
                            <td><strong>Storage Class:</strong></td>
                            <td><code>/api/honeypot/HoneypotJsonStorage.php</code></td>
                        </tr>
                        <tr>
                            <td><strong>Submit Endpoint:</strong></td>
                            <td><code>/api/honeypot/submit.php</code></td>
                        </tr>
                        <tr>
                            <td><strong>Get Endpoint:</strong></td>
                            <td><code>/api/honeypot/messages.php</code></td>
                        </tr>
                        <tr>
                            <td><strong>Admin JSON View:</strong></td>
                            <td><code>/admin/honeypot_json.php</code></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.getElementById('testForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('testUsername').value;
    const message = document.getElementById('testMessage').value;
    
    try {
        const response = await fetch('/socialshield/api/honeypot/submit.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                message: message
            })
        });
        
        const data = await response.json();
        showResponse(data, response.status);
        
    } catch (error) {
        showResponse({ error: error.message }, 500);
    }
});

document.getElementById('getMessagesBtn').addEventListener('click', async function() {
    const limit = document.getElementById('msgLimit').value;
    
    try {
        const response = await fetch(`/socialshield/api/honeypot/messages.php?limit=${limit}`);
        const data = await response.json();
        showResponse(data, response.status);
        
    } catch (error) {
        showResponse({ error: error.message }, 500);
    }
});

function showResponse(data, status) {
    const container = document.getElementById('responseContainer');
    const body = document.getElementById('responseBody');
    
    body.textContent = JSON.stringify(data, null, 2);
    container.style.display = 'block';
}
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
