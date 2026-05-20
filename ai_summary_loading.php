<?php
/**
 * AI_SUMMARY_LOADING.PHP - AI ANALYSIS TRANSITION
 * ----------------------------------------------
 * Provides a high-fidelity loading state while the backend
 * generates a deep AI security report.
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

// [SECURITY] Ensure session is valid
requireLogin();

// [SECURITY] Only allow access via POST from result.php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('result.php');
}

// [SECURITY] CSRF protection
if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
    setFlash('Invalid CSRF token. Please try again.', 'danger');
    redirect('result.php');
}

// [DATA] Ensure scan analysis exists in session
$analysis = $_SESSION['latest_scan_analysis'] ?? $_SESSION['latest_scan_summary'] ?? null;
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

// Flag to allow generate_ai_summary.php to run
$_SESSION['generate_ai_summary_pending'] = true;

// Set page title for consistency
$pageTitle = 'AI Security Assistant';
require_once __DIR__ . '/includes/header.php';
?>

<section class="ss-panel ss-panel-hero">
    <div class="ss-loading-state">
        <div class="ss-spinner ss-spinner--lg" aria-hidden="true"></div>
        <p class="ss-kicker mb-2">AI Security Assistant</p>
        <h1 class="ss-title mb-3">AI analyzing website...</h1>
        <p class="ss-lead mb-0">SocialShield is generating a phishing explanation and security recommendations from the detected threat indicators.</p>
    </div>
</section>

<!-- Automatic redirect to generation script after 1 second of loading animation -->
<meta http-equiv="refresh" content="1;url=<?= e(appPath('generate_ai_summary.php')); ?>">

<?php require_once __DIR__ . '/includes/footer.php'; ?>
