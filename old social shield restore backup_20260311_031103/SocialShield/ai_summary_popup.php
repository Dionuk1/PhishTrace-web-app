<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$analysis = $_SESSION['latest_scan_analysis'] ?? null;
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

$aiReport = generateAiSecurityAssistantReport($analysis);

if (isset($_GET['partial']) && $_GET['partial'] === '1') {
    ?>
    <div class="ss-ai-summary-shell">
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
            <div>
                <h3 class="h5 mb-1">AI Summary</h3>
                <p class="text-muted mb-0"><code><?= e((string) $analysis['url']); ?></code></p>
            </div>
            <span class="badge text-bg-info"><?= e(strtoupper((string) ($aiReport['source'] ?? 'fallback'))); ?></span>
        </div>

        <div class="ss-ai-info-grid mb-3">
            <div class="ss-ai-info-item">
                <span class="ss-ai-info-label">Domain</span>
                <strong><?= e((string) $analysis['domain']); ?></strong>
            </div>
            <div class="ss-ai-info-item">
                <span class="ss-ai-info-label">Risk</span>
                <strong><?= (int) $analysis['risk_score']; ?>/100</strong>
            </div>
            <div class="ss-ai-info-item">
                <span class="ss-ai-info-label">Status</span>
                <strong><?= e(displayStatusLabel((string) $analysis['status'])); ?></strong>
            </div>
        </div>

        <div class="ss-ai-popup-report mb-0">
            <?= renderAiReportHtml((string) $aiReport['text']); ?>
        </div>
    </div>
    <?php
    exit;
}

$pageTitle = 'AI Security Assistant Summary';
require_once __DIR__ . '/includes/header.php';
?>
<div class="row justify-content-center">
    <div class="col-xl-8 col-lg-10">
        <div class="card ss-card">
            <div class="card-body p-4">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                    <div>
                        <h2 class="h4 mb-1">AI Security Assistant</h2>
                        <p class="text-muted mb-0"><code><?= e((string) $analysis['url']); ?></code></p>
                    </div>
                    <span class="badge text-bg-info"><?= e(strtoupper((string) ($aiReport['source'] ?? 'fallback'))); ?></span>
                </div>

                <div class="ss-ai-popup-report mb-3">
                    <?= renderAiReportHtml((string) $aiReport['text']); ?>
                </div>

                <div class="d-flex gap-2 justify-content-end">
                    <a class="btn btn-outline-light" href="<?= e(appPath('result.php')); ?>">Back to Scan Result</a>
                </div>
            </div>
        </div>
    </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
