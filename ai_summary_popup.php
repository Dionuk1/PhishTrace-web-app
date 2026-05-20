<?php
/**
 * AI_SUMMARY_POPUP.PHP - DEEP ANALYSIS WINDOW
 * ------------------------------------------
 * Displays a standalone, detailed AI report for the analyzed URL.
 * Designed to be opened in a modal or popup window.
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

// [SECURITY] Ensure session is valid
requireLogin();

// [DATA] Fetch analysis from session
$analysis = $_SESSION['latest_scan_analysis'] ?? $_SESSION['latest_scan_summary'] ?? null;
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

// [LOGIC] Generate the report (uses fallback heuristics or external AI)
$aiReport = generateAiSecurityAssistantReport($analysis);

// Support for partial loading (AJAX/iFrame)
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
                <span class="ss-ai-info-label">Risk Score</span>
                <strong><?= (int) $analysis['risk_score']; ?>/100</strong>
            </div>
            <div class="ss-ai-info-item">
                <span class="ss-ai-info-label">Status</span>
                <strong><?= e(statusDisplayLabel((string) $analysis['status'])); ?></strong>
            </div>
        </div>

        <div class="ss-ai-popup-report mb-0">
            <?= renderAiReportHtml((string) $aiReport['text']); ?>
        </div>
    </div>
    <?php
    exit;
}

// Full page layout
$pageTitle = 'AI Security Assistant Summary';
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center ss-page-fade-in">
    <div class="col-xl-8 col-lg-10">
        <div class="card ss-console-card">
            <div class="card-body p-4 p-lg-5">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-4">
                    <div>
                        <h2 class="h3 mb-1">AI Security Assistant</h2>
                        <p class="text-secondary mb-0">Detailed investigation for: <code><?= e((string) $analysis['url']); ?></code></p>
                    </div>
                    <span class="ss-status-pill ss-status-pill--ai"><?= e(strtoupper((string) ($aiReport['source'] ?? 'AI-CLUSTER'))); ?></span>
                </div>

                <div class="ss-ai-popup-report mb-4">
                    <?= renderAiReportHtml((string) $aiReport['text']); ?>
                </div>

                <div class="d-flex gap-3 justify-content-end">
                    <button class="btn btn-outline-light" onclick="window.print()">Print Report</button>
                    <a class="btn btn-cyan" href="<?= e(appPath('result.php')); ?>">Back to Dashboard</a>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
