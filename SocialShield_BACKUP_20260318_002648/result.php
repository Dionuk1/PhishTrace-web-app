<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token. Please try again.', 'danger');
        redirect('scan.php');
    }

    $url = sanitizeUrlInput($_POST['url'] ?? '');
    if ($url === '') {
        setFlash('Please submit a valid URL.', 'warning');
        redirect('scan.php');
    }

    $pdo = getPDO();
    $analysis = analyzeUrl($url, $pdo);

    if (!$analysis['valid']) {
        setFlash($analysis['reasons'][0] ?? 'Invalid URL.', 'danger');
        redirect('scan.php');
    }

    $user = currentUser();
    $scanId = saveScan(
        (int) $user['id'],
        $analysis['url'],
        $analysis['domain'],
        (int) $analysis['risk_score'],
        $analysis['status'],
        $analysis['reasons'],
        $pdo
    );

    // Store only minimal scan reference in session - not full analysis with HTML
    $_SESSION['latest_scan_id'] = $scanId;
    $_SESSION['latest_scan_summary'] = [
        'url' => $analysis['url'],
        'domain' => $analysis['domain'],
        'status' => $analysis['status'],
        'risk_score' => $analysis['risk_score'],
        'reasons' => $analysis['reasons'] ?? [],
        'valid' => $analysis['valid'] ?? true,
    ];
    $_SESSION['show_achievement_popup'] = true;
    unset($_SESSION['latest_ai_report']);
} else {
    // Retrieve scan from database instead of session
    $scanId = (int) ($_SESSION['latest_scan_id'] ?? 0);
    $scanSummary = $_SESSION['latest_scan_summary'] ?? null;
    
    if (!is_array($scanSummary) || empty($scanSummary['url'])) {
        redirect('scan.php');
    }
    
    // Reconstruct minimal analysis array from summary
    $analysis = $scanSummary;
    
    // Load full analysis from database only if needed for display
    if ($scanId > 0) {
        $pdo = getPDO();
        $stmt = $pdo->prepare('SELECT url, domain, status, risk_score, reasons FROM scans WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $scanId]);
        $dbScan = $stmt->fetch();
        
        if ($dbScan) {
            $analysis = [
                'url' => $dbScan['url'],
                'domain' => $dbScan['domain'],
                'status' => $dbScan['status'],
                'risk_score' => (int) $dbScan['risk_score'],
                'reasons' => json_decode($dbScan['reasons'], true) ?: [],
                'valid' => true,
            ];
        }
    }
}

// Rebuild threat alerts if needed (without relying on html_analysis from session)
if (empty($analysis['threat_alerts'])) {
    $analysis['threat_alerts'] = buildThreatAlertItems($analysis);
}

$aiReport = $_SESSION['latest_ai_report'] ?? null;
$statusLabel = statusDisplayLabel((string) $analysis['status']);
$riskTone = riskBarTone((string) $analysis['status']);

$showAchievementPopup = !empty($_SESSION['show_achievement_popup']);
if ($showAchievementPopup) {
    unset($_SESSION['show_achievement_popup']);
}

$latestAchievement = null;
if ($showAchievementPopup) {
    $popupUser = currentUser();
    if ($popupUser) {
        $popupData = getUserAchievementNotificationData((int) $popupUser['id'], getPDO());
        $latestAchievement = $popupData['latest_unlock'] ?? null;
    }
}

$pageTitle = 'AI Security Assistant';
require_once __DIR__ . '/includes/header.php';
?>

<section class="ss-panel ss-panel-hero mb-4">
    <div class="d-flex flex-wrap justify-content-between align-items-end gap-3">
        <div>
            <p class="ss-kicker mb-2">AI Security Assistant</p>
            <h1 class="ss-title mb-3">Cybersecurity analysis dashboard</h1>
            <p class="ss-lead mb-0">Professional phishing analysis for <code><?= e($analysis['domain']); ?></code> with threat indicators and on-demand AI explanation.</p>
        </div>
        <div class="ss-chip">SCAN COMPLETE</div>
    </div>
</section>

<section class="card ss-console-card ss-assistant-dashboard">
    <div class="card-body p-4 p-lg-5">
        <div class="row g-4">
            <div class="col-lg-5">
                <div class="ss-assistant-section h-100">
                    <div class="ss-section-header">
                        <span class="ss-section-icon">SCAN</span>
                        <div>
                            <h2 class="h4 mb-1">URL Scan Result</h2>
                            <p class="text-secondary mb-0">Live phishing analysis for the submitted link.</p>
                        </div>
                    </div>

                    <div class="ss-result-meta">
                        <div class="ss-result-meta-row">
                            <span>Submitted URL</span>
                            <code><?= e($analysis['url']); ?></code>
                        </div>
                        <div class="ss-result-meta-row">
                            <span>Detected domain</span>
                            <strong><?= e($analysis['domain']); ?></strong>
                        </div>
                        <div class="ss-result-meta-row">
                            <span>Risk status</span>
                            <span class="ss-status-pill ss-status-pill--<?= e($riskTone); ?>"><?= e($statusLabel); ?></span>
                        </div>
                    </div>

                    <div class="ss-risk-meter">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="ss-metric-label mb-0">Risk Score</span>
                            <span class="ss-risk-percent ss-risk-percent--<?= e($riskTone); ?>"><?= (int) $analysis['risk_score']; ?>%</span>
                        </div>
                        <div class="ss-progress-track" aria-hidden="true">
                            <div class="ss-progress-bar ss-progress-bar--<?= e($riskTone); ?>" style="width: <?= (int) $analysis['risk_score']; ?>%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-7">
                <div class="ss-assistant-section h-100">
                    <div class="ss-section-header">
                        <span class="ss-section-icon ss-section-icon--warning">THREAT</span>
                        <div>
                            <h2 class="h4 mb-1">Threat Indicators</h2>
                            <p class="text-secondary mb-0">Detected signals commonly associated with phishing or malicious pages.</p>
                        </div>
                    </div>

                    <ul class="ss-threat-list mb-0">
                        <?php foreach (($analysis['threat_alerts'] ?? []) as $alert): ?>
                            <li class="ss-threat-item ss-threat-item--<?= e((string) $alert['tone']); ?>">
                                <span class="ss-threat-icon"><?= e((string) $alert['icon']); ?></span>
                                <span><?= e((string) $alert['text']); ?></span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        </div>

        <div class="ss-assistant-divider"></div>

        <div class="ss-assistant-section">
            <div class="ss-section-header">
                <span class="ss-section-icon ss-section-icon--ai">AI</span>
                <div>
                    <h2 class="h4 mb-1">AI Security Assistant</h2>
                    <p class="text-secondary mb-0">Generate a natural-language explanation and recommendations from the detected indicators.</p>
                </div>
            </div>

            <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
                <form method="post" action="<?= e(appPath('ai_summary_loading.php')); ?>" class="m-0">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <button type="submit" class="btn btn-primary ss-ai-trigger">Generate AI Summary</button>
                </form>
                <a href="<?= e(appPath('ai_summary_popup.php')); ?>" class="btn btn-outline-light btn-sm" target="_blank" onclick="window.open(this.href,'aiSummaryPopup','width=980,height=780'); return false;">Open AI Summary Popup</a>
                <span class="ss-chip">Source: OpenAI or fallback security model</span>
            </div>

            <?php if ($aiReport): ?>
                <div class="ss-ai-summary-box mt-3">
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                        <h3 class="h5 mb-0">AI Summary</h3>
                        <span class="ss-status-pill ss-status-pill--ai"><?= e(strtoupper((string) $aiReport['source'])); ?></span>
                    </div>
                    <div class="ss-ai-summary-content"><?= renderAiReportHtml((string) $aiReport['text']); ?></div>
                </div>
            <?php else: ?>
                <div class="ss-ai-placeholder mt-3">
                    <span class="ss-spinner" aria-hidden="true"></span>
                    <div>
                        <strong>AI summary ready on request</strong>
                        <p class="mb-0 text-secondary">Submit the button above to generate a PHP-rendered explanation from the current threat indicators.</p>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>
</section>

<div class="d-grid gap-2 d-md-flex mt-4">
    <a href="<?= e(appPath('scan.php')); ?>" class="btn btn-primary">Scan Another URL</a>
    <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light">View Scan History</a>
</div>

<?php if ($showAchievementPopup && is_array($latestAchievement)): ?>
<div class="modal fade" id="achievementPopup" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content ss-panel">
            <div class="modal-header border-0">
                <h5 class="modal-title">Achievement Unlocked</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <h4 class="mb-2"><?= e((string) $latestAchievement['title']); ?></h4>
                <p class="text-secondary mb-2"><?= e((string) $latestAchievement['description']); ?></p>
                <span class="badge text-bg-success">+<?= (int) $latestAchievement['points']; ?> pts</span>
            </div>
        </div>
    </div>
</div>
<script>
    document.addEventListener('DOMContentLoaded', function () {
        var popupEl = document.getElementById('achievementPopup');
        if (!popupEl || typeof bootstrap === 'undefined') return;

        var modal = new bootstrap.Modal(popupEl);
        var autoCloseTimer = null;
        var closeDelay = 12000;

        var clearAutoClose = function () {
            if (autoCloseTimer !== null) {
                window.clearTimeout(autoCloseTimer);
                autoCloseTimer = null;
            }
        };

        popupEl.addEventListener('hidden.bs.modal', clearAutoClose, { once: true });

        modal.show();

        autoCloseTimer = window.setTimeout(function () {
            modal.hide();
        }, closeDelay);
    });
</script>
<?php endif; ?>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
