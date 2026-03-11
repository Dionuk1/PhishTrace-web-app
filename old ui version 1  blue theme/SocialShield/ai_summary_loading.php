<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('result.php');
}

if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
    setFlash('Invalid CSRF token. Please try again.', 'danger');
    redirect('result.php');
}

$analysis = $_SESSION['latest_scan_analysis'] ?? null;
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

$_SESSION['generate_ai_summary_pending'] = true;

$pageTitle = 'AI Security Assistant';
require_once __DIR__ . '/includes/header.php';
?>

<section class="ss-panel ss-panel-hero">
    <div class="ss-loading-state">
        <span class="ss-spinner ss-spinner--lg" aria-hidden="true"></span>
        <p class="ss-kicker mb-2">AI Security Assistant</p>
        <h1 class="ss-title mb-3">AI analyzing website...</h1>
        <p class="ss-lead mb-0">SocialShield is generating a phishing explanation and security recommendations from the detected threat indicators.</p>
    </div>
</section>

<meta http-equiv="refresh" content="1;url=<?= e(appPath('generate_ai_summary.php')); ?>">

<?php require_once __DIR__ . '/includes/footer.php'; ?>

