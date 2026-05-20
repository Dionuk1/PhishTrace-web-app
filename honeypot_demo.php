<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

$pageTitle = 'Social Media Honeypot Demo';
require_once __DIR__ . '/includes/header.php';
?>

<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-lg-7">
            <div class="mb-4">
                <h1 class="h3 fw-bold mb-2">Social Media Honeypot Demo</h1>
                <p class="text-muted mb-0">Submit a demo message to test rule-based suspicious message and phishing detection.</p>
            </div>

            <div id="honeypotAlert" class="alert d-none" role="alert"></div>

            <div class="card ss-card">
                <div class="card-body p-4">
                    <form id="honeypotDemoForm">
                        <div class="mb-3">
                            <label for="honeypotUsername" class="form-label fw-semibold">Username</label>
                            <input type="text" class="form-control" id="honeypotUsername" name="username" maxlength="50" required>
                        </div>

                        <div class="mb-3">
                            <label for="honeypotMessage" class="form-label fw-semibold">Message</label>
                            <textarea class="form-control" id="honeypotMessage" name="message" rows="6" maxlength="5000" required></textarea>
                        </div>

                        <button type="submit" class="btn btn-primary">Analyze Message</button>
                        <a href="<?= e(appPath('admin/honeypot_dashboard.php')); ?>" class="btn btn-outline-secondary ms-2">View Dashboard</a>
                    </form>
                </div>
            </div>

            <div id="honeypotResult" class="card ss-card mt-4 d-none">
                <div class="card-header fw-semibold">Analysis Result</div>
                <div class="card-body">
                    <p class="mb-2"><strong>Risk:</strong> <span id="resultRisk"></span></p>
                    <p class="mb-2"><strong>Keywords:</strong> <span id="resultKeywords"></span></p>
                    <p class="mb-0"><strong>URLs:</strong> <span id="resultUrls"></span></p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.getElementById('honeypotDemoForm').addEventListener('submit', async function (event) {
    event.preventDefault();

    const alertBox = document.getElementById('honeypotAlert');
    const resultBox = document.getElementById('honeypotResult');
    const formData = new FormData(event.target);

    alertBox.className = 'alert alert-info';
    alertBox.textContent = 'Analyzing message...';
    resultBox.classList.add('d-none');

    try {
        const response = await fetch('<?= e(appPath('api/honeypot/submit.php')); ?>', {
            method: 'POST',
            body: formData
        });
        const payload = await response.json();

        if (!payload.success) {
            alertBox.className = 'alert alert-warning';
            alertBox.textContent = payload.error || payload.message || 'Message could not be saved.';
            return;
        }

        const data = payload.data || {};
        alertBox.className = 'alert alert-success';
        alertBox.textContent = 'Message saved and analyzed.';

        document.getElementById('resultRisk').textContent = `${data.risk_level} (${data.risk_score})`;
        document.getElementById('resultKeywords').textContent = (data.detected_keywords || []).join(', ') || 'None';
        document.getElementById('resultUrls').textContent = (data.extracted_urls || []).join(', ') || 'None';
        resultBox.classList.remove('d-none');
        event.target.reset();
    } catch (error) {
        alertBox.className = 'alert alert-danger';
        alertBox.textContent = 'Request failed. Please try again.';
    }
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
