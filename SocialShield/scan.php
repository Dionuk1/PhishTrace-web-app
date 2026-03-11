<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pageTitle = 'Scan URL';
require_once __DIR__ . '/includes/header.php';
?>

<section class="ss-panel ss-panel-hero mb-4">
    <div class="row align-items-center g-4">
        <div class="col-lg-7">
            <p class="ss-kicker mb-2">AI Security Assistant</p>
            <h1 class="ss-title mb-3">Analyze suspicious websites like a phishing investigation dashboard.</h1>
            <p class="ss-lead mb-0">
                PhishTrace fetches the live page, checks threat indicators, and generates a human-readable AI security explanation.
            </p>
        </div>
        <div class="col-lg-5">
            <div class="ss-metric-grid">
                <div class="ss-metric-card">
                    <span class="ss-metric-label">Checks</span>
                    <strong>URL + HTML + SSL</strong>
                </div>
                <div class="ss-metric-card">
                    <span class="ss-metric-label">Indicators</span>
                    <strong>Phishing + Brand + Wallet</strong>
                </div>
                <div class="ss-metric-card">
                    <span class="ss-metric-label">Output</span>
                    <strong>Risk Score + AI Report</strong>
                </div>
            </div>
        </div>
    </div>
</section>

<div class="row justify-content-center">
    <div class="col-xl-9">
        <div class="card ss-console-card">
            <div class="card-body p-4 p-lg-5">
                <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-4">
                    <div>
                        <h2 class="h4 mb-2">URL Scanner</h2>
                        <p class="text-secondary mb-0">Example: <code>https://example.com/login</code></p>
                    </div>
                    <span class="ss-chip">Live HTML inspection enabled</span>
                </div>

                <form action="<?= e(appPath('result.php')); ?>" method="post" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <div class="mb-4">
                        <label for="url" class="form-label text-uppercase small fw-semibold">Suspicious URL</label>
                        <input
                            type="url"
                            class="form-control form-control-lg ss-input"
                            id="url"
                            name="url"
                            required
                            placeholder="https://your-link-here.com">
                    </div>
                    <div class="d-flex flex-wrap gap-3 align-items-center">
                        <button type="submit" class="btn btn-primary btn-lg px-4">Run Security Scan</button>
                        <span class="text-secondary small">The scanner checks domain traits, page content, and AI risk explanation.</span>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

