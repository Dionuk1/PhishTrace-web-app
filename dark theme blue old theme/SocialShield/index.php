<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
$pageTitle = 'Home';
require_once __DIR__ . '/includes/header.php';
?>

<section class="p-5 mb-4 rounded-4 ss-hero">
    <div class="container-fluid py-4">
        <div class="row g-4 align-items-stretch">
            <div class="col-lg-7">
                <div class="ss-hero-main h-100">
                    <h1 class="display-5 fw-bold">Stay safer on social networks with PhishTrace</h1>
                    <p class="fs-5 ss-hero-copy">
                        This beginner-friendly web app demonstrates rule-based phishing link detection,
                        privacy awareness, and secure coding basics in PHP.
                    </p>
                    <div class="d-flex gap-3 flex-wrap ss-hero-actions">
                        <a href="<?= e(appPath('scan.php')); ?>" class="btn ss-btn-hero-primary btn-lg">Scan a URL</a>
                        <a href="<?= e(appPath('honeypot.php')); ?>" class="btn ss-btn-hero-secondary btn-lg">📨 Send Tip</a>
                        <a href="<?= e(appPath('tips.php')); ?>" class="btn ss-btn-hero-secondary btn-lg">Read Security Tips</a>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                <aside class="ss-hero-side h-100" aria-label="Quick security tips">
                    <p class="ss-kicker mb-3">Quick Security Checks</p>
                    <div class="ss-hero-tip-list">
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">2FA</span>
                            <div>
                                <h3 class="h6 mb-1">Add 2FA to your accounts</h3>
                                <p class="mb-0">Turn on two-factor authentication on every social account.</p>
                            </div>
                        </div>
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">LINK</span>
                            <div>
                                <h3 class="h6 mb-1">Check links before clicking</h3>
                                <p class="mb-0">Verify the domain manually before logging in or opening a page.</p>
                            </div>
                        </div>
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">PASS</span>
                            <div>
                                <h3 class="h6 mb-1">Use strong unique passwords</h3>
                                <p class="mb-0">Avoid reusing the same password across social and email accounts.</p>
                            </div>
                        </div>
                    </div>
                </aside>
            </div>
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

