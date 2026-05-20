<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/honeypot_functions.php';
requireLogin();
requireAdmin();

$pdo = getPDO();
$pageTitle = 'Social Media Honeypot';

// Initialize honeypot table
initHoneypotTable($pdo);

// Handle form submissions
$message = null;
$messageType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    $token = (string) ($_POST['csrf_token'] ?? '');

    if (!verifyCsrfToken($token)) {
        $message = 'Invalid CSRF token.';
        $messageType = 'danger';
    } elseif ($action === 'add_message') {
        $senderInfo = trim((string) ($_POST['sender_info'] ?? ''));
        $messageText = trim((string) ($_POST['message_text'] ?? ''));

        if ($senderInfo === '' || $messageText === '') {
            $message = 'Sender info and message are required.';
            $messageType = 'warning';
        } else {
            logHoneypotMessage($pdo, $senderInfo, $messageText);
            $message = 'Honeypot message logged successfully.';
            $messageType = 'success';
        }
    } elseif ($action === 'delete_log') {
        $logId = (int) ($_POST['log_id'] ?? 0);
        if ($logId > 0) {
            deleteHoneypotLog($pdo, $logId);
            $message = 'Log entry deleted.';
            $messageType = 'success';
        }
    }
}

// Get honeypot data
$stats = getHoneypotStats($pdo);
$recentLogs = getHoneypotLogs($pdo, 10, 0);
$topKeywords = getTopHoneypotKeywords($pdo, 10);
$suspiciousUrls = getSuspiciousHoneypotUrls($pdo, 10);

require_once __DIR__ . '/../includes/header.php';
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2 class="h4 mb-0">🍯 Social Media Honeypot</h2>
        <small class="text-muted">Track phishing attempts & spam messages</small>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= e($messageType); ?> alert-dismissible fade show" role="alert">
            <?= e($message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Statistics Cards -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card ss-card border-left-primary">
                <div class="card-body">
                    <h5 class="card-title">Total Messages</h5>
                    <p class="display-6 mb-0"><?= (int) $stats['total_messages']; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-danger">
                <div class="card-body">
                    <h5 class="card-title">High Risk (>80)</h5>
                    <p class="display-6 mb-0"><?= (int) $stats['high_risk_count']; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-warning">
                <div class="card-body">
                    <h5 class="card-title">Unique IPs</h5>
                    <p class="display-6 mb-0"><?= (int) $stats['unique_ips']; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card ss-card border-left-info">
                <div class="card-body">
                    <h5 class="card-title">Unique URLs</h5>
                    <p class="display-6 mb-0"><?= (int) $stats['unique_urls']; ?></p>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-3 mb-4">
        <!-- Add Message Form -->
        <div class="col-md-6">
            <div class="card ss-card">
                <div class="card-header">
                    <h5 class="mb-0">📨 Simulate Honeypot Message</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="action" value="add_message">

                        <div class="mb-3">
                            <label class="form-label">Sender Info (e.g., @username, email)</label>
                            <input type="text" class="form-control" name="sender_info" placeholder="@attacker or attacker@example.com" required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Message Text</label>
                            <textarea class="form-control" name="message_text" rows="4" placeholder="Paste suspicious message here..." required></textarea>
                            <small class="text-muted d-block mt-1">URLs and keywords will be extracted automatically</small>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">
                            <span class="me-2">📝</span> Log Message
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Top Keywords -->
        <div class="col-md-6">
            <div class="card ss-card">
                <div class="card-header">
                    <h5 class="mb-0">🔑 Top Keywords Detected</h5>
                </div>
                <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                    <?php if ($topKeywords): ?>
                        <div class="list-group list-group-flush">
                            <?php foreach ($topKeywords as $item): ?>
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <span><?= e((string) ($item['keyword'] ?? '')); ?></span>
                                    <span class="badge bg-danger"><?= (int) ($item['count'] ?? 0); ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <p class="text-muted text-center py-3">No keywords detected yet</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Suspicious URLs Table -->
    <div class="card ss-card mb-4">
        <div class="card-header">
            <h5 class="mb-0">🔗 Suspicious URLs Extracted</h5>
        </div>
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th>URL</th>
                        <th>Times Seen</th>
                        <th>Domain</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($suspiciousUrls): ?>
                        <?php foreach ($suspiciousUrls as $item): ?>
                            <tr>
                                <td>
                                    <small class="text-monospace">
                                        <?= e(substr((string) ($item['url'] ?? ''), 0, 50)); ?>
                                        <?php if (strlen((string) ($item['url'] ?? '')) > 50): ?>...<?php endif; ?>
                                    </small>
                                </td>
                                <td>
                                    <span class="badge bg-warning"><?= (int) ($item['count'] ?? 0); ?></span>
                                </td>
                                <td><code><?= e((string) ($item['domain'] ?? 'N/A')); ?></code></td>
                                <td><small><?= e(substr((string) ($item['first_seen'] ?? ''), 0, 10)); ?></small></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted py-3">No URLs extracted yet</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="card ss-card mb-4">
        <div class="card-header">
            <div class="d-flex justify-content-between align-items-center">
                <h5 class="mb-0">📋 Recent Activity</h5>
                <a href="<?= e(appPath('admin/honeypot.php?page=all')); ?>" class="btn btn-sm btn-outline-secondary">View All</a>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th>Sender</th>
                        <th>Message (Preview)</th>
                        <th>Risk Score</th>
                        <th>Keywords</th>
                        <th>URLs</th>
                        <th>Time</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($recentLogs): ?>
                        <?php foreach ($recentLogs as $log): ?>
                            <?php
                            $riskScore = (int) ($log['risk_score'] ?? 0);
                            $riskClass = $riskScore >= 80 ? 'danger' : ($riskScore >= 50 ? 'warning' : 'success');
                            $keywords = !empty($log['detected_keywords']) ? json_decode((string) ($log['detected_keywords'] ?? '[]'), true) : [];
                            $urls = !empty($log['extracted_url']) ? json_decode((string) ($log['extracted_url'] ?? '[]'), true) : [];
                            ?>
                            <tr>
                                <td>
                                    <strong><?= e((string) ($log['sender_info'] ?? 'Unknown')); ?></strong>
                                </td>
                                <td>
                                    <small>
                                        <?= e(substr((string) ($log['message_text'] ?? ''), 0, 60)); ?>
                                        <?php if (strlen((string) ($log['message_text'] ?? '')) > 60): ?>...<?php endif; ?>
                                    </small>
                                </td>
                                <td>
                                    <span class="badge bg-<?= e($riskClass); ?>">
                                        <?php if ($riskScore >= 80): ?>
                                            🔴 <?= e((string) $riskScore); ?>
                                        <?php elseif ($riskScore >= 50): ?>
                                            🟡 <?= e((string) $riskScore); ?>
                                        <?php else: ?>
                                            🟢 <?= e((string) $riskScore); ?>
                                        <?php endif; ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($keywords): ?>
                                        <small>
                                            <?php foreach (array_slice($keywords, 0, 2) as $kw): ?>
                                                <span class="badge bg-light text-dark"><?= e((string) $kw); ?></span>
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
                                    <?php if ($urls): ?>
                                        <small><?= count($urls); ?> URL<?= count($urls) !== 1 ? 's' : ''; ?></small>
                                    <?php else: ?>
                                        <small class="text-muted">—</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <small class="text-muted"><?= e(substr((string) ($log['created_at'] ?? ''), 5, 11)); ?></small>
                                </td>
                                <td>
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                        <input type="hidden" name="action" value="delete_log">
                                        <input type="hidden" name="log_id" value="<?= (int) ($log['id'] ?? 0); ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this entry?');">🗑</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="7" class="text-center text-muted py-4">No honeypot messages recorded yet</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Filter & Search (Advanced) -->
    <div class="card ss-card">
        <div class="card-header">
            <h5 class="mb-0">🔍 Filter & Search</h5>
        </div>
        <div class="card-body">
            <form method="GET" class="row g-2">
                <div class="col-md-3">
                    <label class="form-label">Min Risk Score</label>
                    <input type="number" class="form-control" name="min_risk" min="0" max="100" value="<?= e((string) ($_GET['min_risk'] ?? '')); ?>" placeholder="0">
                </div>
                <div class="col-md-3">
                    <label class="form-label">Max Risk Score</label>
                    <input type="number" class="form-control" name="max_risk" min="0" max="100" value="<?= e((string) ($_GET['max_risk'] ?? '')); ?>" placeholder="100">
                </div>
                <div class="col-md-3">
                    <label class="form-label">Search Keywords</label>
                    <input type="text" class="form-control" name="keyword" placeholder="e.g., verify, win, click" value="<?= e((string) ($_GET['keyword'] ?? '')); ?>">
                </div>
                <div class="col-md-3">
                    <label class="form-label">&nbsp;</label>
                    <button type="submit" class="btn btn-primary w-100">Search</button>
                </div>
            </form>
        </div>
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
    .text-monospace {
        font-family: 'Courier New', monospace;
        word-break: break-all;
    }
    .ss-card {
        border: 1px solid #e0e0e0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
</style>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
