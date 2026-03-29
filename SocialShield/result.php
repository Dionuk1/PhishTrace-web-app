<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('scan.php');
    }

    $userId = (string) ($_SESSION['user_id'] ?? 'guest');
    if (!checkRateLimit('scan_' . $userId, 10, 60)) {
        setFlash(t('too_many_scan'), 'warning');
        redirect('scan.php');
    }

    $url = sanitizeUrlInput($_POST['url'] ?? '');
    if ($url === '') {
        setFlash(t('invalid_url'), 'warning');
        redirect('scan.php');
    }

    $pdo = getPDO();
    $analysis = analyzeUrl($url, $pdo);

    if (!$analysis['valid']) {
        setFlash($analysis['reasons'][0] ?? t('invalid_url'), 'danger');
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

$pageTitle = t('ai_assistant');
require_once __DIR__ . '/includes/header.php';
?>

<section class="ss-panel ss-panel-hero mb-4">
    <div class="d-flex flex-wrap justify-content-between align-items-end gap-3">
        <div>
            <p class="ss-kicker mb-2"><?= e(t('ai_assistant')); ?></p>
            <h1 class="ss-title mb-3"><?= e(t('analysis_dashboard')); ?></h1>
            <p class="ss-lead mb-0"><?= e(t('analysis_lead')); ?></p>
        </div>
        <div class="ss-chip"><?= e(t('scan_complete')); ?></div>
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
                            <h2 class="h4 mb-1"><?= e(t('result_title')); ?></h2>
                            <p class="text-secondary mb-0"><?= e(t('result_desc')); ?></p>
                        </div>
                    </div>

                    <div class="ss-result-meta">
                        <div class="ss-result-meta-row">
                            <span><?= e(t('submitted_url')); ?></span>
                            <code><?= e($analysis['url']); ?></code>
                        </div>
                        <div class="ss-result-meta-row">
                            <span><?= e(t('detected_domain')); ?></span>
                            <strong><?= e($analysis['domain']); ?></strong>
                        </div>
                        <div class="ss-result-meta-row">
                            <span><?= e(t('risk_status')); ?></span>
                            <span class="ss-status-pill ss-status-pill--<?= e($riskTone); ?>"><?= e($statusLabel); ?></span>
                        </div>
                    </div>

                    <div class="ss-risk-meter">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="ss-metric-label mb-0"><?= e(t('risk_score')); ?></span>
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
                            <h2 class="h4 mb-1"><?= e(t('threat_indicators')); ?></h2>
                            <p class="text-secondary mb-0"><?= e(t('threat_desc')); ?></p>
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
                    <h2 class="h4 mb-1"><?= e(t('ai_assistant')); ?></h2>
                    <p class="text-secondary mb-0"><?= e(t('ai_desc')); ?></p>
                </div>
            </div>

            <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
                <form method="post" action="<?= e(appPath('ai_summary_loading.php')); ?>" class="m-0">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <button type="submit" class="btn btn-primary ss-ai-trigger"><?= e(t('generate_ai')); ?></button>
                </form>
                <a href="<?= e(appPath('ai_summary_popup.php')); ?>" class="btn btn-outline-light btn-sm" target="_blank" onclick="window.open(this.href,'aiSummaryPopup','width=980,height=780'); return false;"><?= e(t('open_popup')); ?></a>
                <span class="ss-chip"><?= e(t('ai_source')); ?></span>
            </div>

            <?php if ($aiReport): ?>
                <div class="ss-ai-summary-box mt-3">
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                        <h3 class="h5 mb-0"><?= e(t('ai_summary')); ?></h3>
                        <span class="ss-status-pill ss-status-pill--ai"><?= e(strtoupper((string) $aiReport['source'])); ?></span>
                    </div>
                    <div class="ss-ai-summary-content"><?= renderAiReportHtml((string) $aiReport['text']); ?></div>
                </div>
            <?php else: ?>
                <div class="ss-ai-placeholder mt-3">
                    <span class="ss-spinner" aria-hidden="true"></span>
                    <div>
                        <strong><?= e(t('ai_ready')); ?></strong>
                        <p class="mb-0 text-secondary"><?= e(t('ai_trigger_desc')); ?></p>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>
</section>

<div class="d-grid gap-2 d-md-flex mt-4">
    <a href="<?= e(appPath('scan.php')); ?>" class="btn btn-primary"><?= e(t('scan_another')); ?></a>
    <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light"><?= e(t('view_scan_history')); ?></a>
</div>

<?php if ($showAchievementPopup && is_array($latestAchievement)): ?>
<div class="modal fade" id="achievementPopup" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content ss-panel">
            <div class="modal-header border-0">
                <h5 class="modal-title"><?= e(t('achievement_unlocked')); ?></h5>
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
