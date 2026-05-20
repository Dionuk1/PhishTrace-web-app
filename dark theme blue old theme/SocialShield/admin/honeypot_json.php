<?php
/**
 * Admin dashboard for viewing honeypot messages stored in JSON
 * Alternative view for JSON-based storage
 */

declare(strict_types=1);

require_once __DIR__ . '/api/honeypot/HoneypotJsonStorage.php';

$pageTitle = 'Honeypot Messages (JSON View)';

// Initialize storage
$dataDir = __DIR__ . '/data';
$storage = new HoneypotJsonStorage($dataDir);

// Get all messages
$messages = $storage->getAllMessages();
$totalMessages = count($messages);

// Get statistics
$highRiskCount = 0;
$urlCount = 0;
$lowRiskCount = 0;
$mediumRiskCount = 0;
$highRiskLevelCount = 0;
foreach ($messages as $msg) {
    // Count messages with keywords
    if (!empty($msg['detected_keywords'] ?? [])) {
        $highRiskCount++;
    }
    // Count total unique URLs
    $urls = $msg['extracted_urls'] ?? [];
    if (!empty($urls)) {
        $urlCount += count($urls);
    }

    // Count risk levels (from auto-scoring)
    $riskLevel = (string) ($msg['risk_level'] ?? 'Low');
    if ($riskLevel === 'High') {
        $highRiskLevelCount++;
    } elseif ($riskLevel === 'Medium') {
        $mediumRiskCount++;
    } else {
        $lowRiskCount++;
    }
}

require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="h4 mb-0">📊 Honeypot Messages (JSON Storage)</h2>
        <div class="btn-group" role="group">
            <a href="<?= e(appPath('admin/honeypot.php')); ?>" class="btn btn-outline-primary btn-sm">Database View</a>
            <button type="button" class="btn btn-outline-secondary btn-sm" disabled>JSON View (Active)</button>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card ss-card border-left-primary">
                <div class="card-body">
                    <h5 class="card-title">Total Messages</h5>
                    <p class="display-6 mb-0"><?= $totalMessages; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-danger">
                <div class="card-body">
                    <h5 class="card-title">With Keywords</h5>
                    <p class="display-6 mb-0"><?= $highRiskCount; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-warning">
                <div class="card-body">
                    <h5 class="card-title">URLs Detected</h5>
                    <p class="display-6 mb-0"><?= $urlCount; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-info">
                <div class="card-body">
                    <h5 class="card-title">Storage Type</h5>
                    <p class="display-6 mb-0" style="font-size: 1rem;">JSON File</p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-secondary">
                <div class="card-body">
                    <h5 class="card-title">Risk Levels</h5>
                    <div class="d-flex flex-column gap-1">
                        <small><span class="badge bg-success">Low</span> <?= $lowRiskCount; ?></small>
                        <small><span class="badge bg-warning text-dark">Medium</span> <?= $mediumRiskCount; ?></small>
                        <small><span class="badge bg-danger">High</span> <?= $highRiskLevelCount; ?></small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Messages Table -->
    <div class="card ss-card">
        <div class="card-header">
            <h5 class="mb-0">📋 All Messages</h5>
        </div>
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th style="width: 50px;">ID</th>
                        <th>Username</th>
                        <th>Message Preview</th>
                        <th>Keywords</th>
                        <th>URLs</th>
                        <th style="width: 80px;">Score</th>
                        <th style="width: 90px;">Risk</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($messages): ?>
                        <?php foreach (array_reverse($messages) as $msg): ?>
                            <tr>
                                <td>
                                    <small class="text-monospace fw-bold">#<?= (int) ($msg['id'] ?? 0); ?></small>
                                </td>
                                <td>
                                    <strong><?= e((string) ($msg['username'] ?? 'Unknown')); ?></strong>
                                </td>
                                <td>
                                    <small>
                                        <?= e(substr((string) ($msg['message'] ?? ''), 0, 50)); ?>
                                        <?php if (strlen((string) ($msg['message'] ?? '')) > 50): ?>...<?php endif; ?>
                                    </small>
                                </td>
                                <td>
                                    <?php
                                    $keywords = $msg['detected_keywords'] ?? [];
                                    if (!empty($keywords)):
                                    ?>
                                        <small>
                                            <?php foreach (array_slice($keywords, 0, 2) as $kw): ?>
                                                <span class="badge bg-danger text-white"><?= e((string) $kw); ?></span>
                                            <?php endforeach; ?>
                                            <?php if (count($keywords) > 2): ?>
                                                <span class="badge bg-light text-dark">+<?= count($keywords) - 2; ?></span>
                                            <?php endif; ?>
                                        </small>
                                    <?php else: ?>
                                        <small class="text-muted">—</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php
                                    $urls = $msg['extracted_urls'] ?? [];
                                    if (!empty($urls)):
                                    ?>
                                        <small>
                                            <?php foreach (array_slice($urls, 0, 1) as $url): ?>
                                                <span class="badge bg-info text-white" title="<?= e($url); ?>">
                                                    🔗 <?= e(substr($url, 0, 25)); ?>...
                                                </span>
                                            <?php endforeach; ?>
                                            <?php if (count($urls) > 1): ?>
                                                <span class="badge bg-secondary"> +<?= count($urls) - 1; ?></span>
                                            <?php endif; ?>
                                        </small>
                                    <?php else: ?>
                                        <small class="text-muted">—</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <small class="text-monospace fw-bold"><?= (int) ($msg['risk_score'] ?? 0); ?></small>
                                </td>
                                <td>
                                    <?php
                                    $riskLevel = (string) ($msg['risk_level'] ?? 'Low');
                                    $riskBadgeClass = 'bg-success';
                                    if ($riskLevel === 'Medium') {
                                        $riskBadgeClass = 'bg-warning text-dark';
                                    } elseif ($riskLevel === 'High') {
                                        $riskBadgeClass = 'bg-danger';
                                    }
                                    ?>
                                    <span class="badge <?= e($riskBadgeClass); ?>"><?= e($riskLevel); ?></span>
                                </td>
                                <td>
                                    <small class="text-muted"><?= e((string) ($msg['timestamp'] ?? '')); ?></small>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="8" class="text-center text-muted py-4">
                                No messages yet. Visitors can send messages via the honeypot form.
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Info Section -->
    <div class="mt-4 alert alert-info">
        <h6 class="alert-heading">ℹ️ Monitored Keywords</h6>
        <p class="mb-2">
            The system scans every message for these suspicious keywords:
        </p>
        <div>
            <?php foreach ($storage->getSuspiciousKeywords() as $kw): ?>
                <span class="badge bg-info text-white me-1"><?= e((string) $kw); ?></span>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Info Section -->
    <div class="mt-2 alert alert-warning">
        <h6 class="alert-heading">🔗 URL Detection</h6>
        <p class="mb-0">
            The system automatically extracts all HTTP and HTTPS links from messages.
            This helps identify phishing attempts and malicious URLs.
        </p>
    </div>

    <!-- Info Section -->
    <div class="mt-2 alert alert-secondary">
        <h6 class="alert-heading">📂 JSON Storage Details</h6>
        <p class="mb-0">
            Messages are stored in <code><?= e($storage->getStoragePath()); ?></code><br>
            Each message includes: id, username, message, detected_keywords, keyword_count, extracted_urls, url_count, risk_score, risk_level, timestamp, received_at
        </p>
    </div>
</div>

<style>
    .border-left-primary {
        border-left: 4px solid #0d6efd !important;
    }
    .border-left-danger {
        border-left: 4px solid #dc3545 !important;
    }
    .border-left-warning {
        border-left: 4px solid #ffc107 !important;
    }
    .border-left-info {
        border-left: 4px solid #0dcaf0 !important;
    }
    .border-left-secondary {
        border-left: 4px solid #6c757d !important;
    }
    .text-monospace {
        font-family: 'Courier New', monospace;
    }
    .ss-card {
        border: 1px solid #e0e0e0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
</style>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
