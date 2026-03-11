<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
$pageTitle = 'Home';
require_once __DIR__ . '/includes/header.php';
?>

<section class="p-5 mb-4 rounded-4 ss-hero">
    <div class="container-fluid py-4">
        <h1 class="display-5 fw-bold">Stay safer on social networks with PhishTrace</h1>
        <p class="col-lg-8 fs-5">
            This beginner-friendly web app demonstrates rule-based phishing link detection,
            privacy awareness, and secure coding basics in PHP.
        </p>
        <div class="d-flex gap-2 flex-wrap">
            <a href="<?= e(appPath('scan.php')); ?>" class="btn btn-warning btn-lg">Scan a URL</a>
            <a href="<?= e(appPath('tips.php')); ?>" class="btn btn-outline-light btn-lg">Read Security Tips</a>
        </div>
    </div>
</section>

<div class="row g-4">
    <div class="col-md-4">
        <div class="card h-100 shadow-sm">
            <div class="card-body">
                <h5 class="card-title">1. Submit Link</h5>
                <p class="card-text">Paste any URL and run a quick risk analysis using predefined scam indicators.</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100 shadow-sm">
            <div class="card-body">
                <h5 class="card-title">2. Understand Risk</h5>
                <p class="card-text">Get score, status badge, and reasons that explain why a link may be suspicious.</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100 shadow-sm">
            <div class="card-body">
                <h5 class="card-title">3. Learn Safe Habits</h5>
                <p class="card-text">Review privacy and security recommendations for social media usage.</p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

