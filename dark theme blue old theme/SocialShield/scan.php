<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pageTitle = 'Scan URL';
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center ss-scan-stage">
    <div class="col-xl-9 col-lg-10">
        <section class="ss-panel ss-panel-hero ss-scan-card">
            <div class="ss-scan-card__glow" aria-hidden="true"></div>
            <div class="ss-scan-intro">
                <h1 class="ss-title mb-3">Skano nj&#235; link t&#235; dyshimt&#235;</h1>
                <p class="ss-lead mb-4">SocialShield kontrollon URL-n&#235;, treguesit e skanimit dhe modelet e dyshimta p&#235;rpara se t&#235; klikosh.</p>
            </div>

            <form action="<?= e(appPath('result.php')); ?>" method="post" novalidate>
                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                <div class="mb-4">
                    <label for="url" class="form-label ss-scan-label">URL p&#235;r skanim</label>
                    <input type="url" class="form-control form-control-lg ss-input ss-scan-input" id="url" name="url" placeholder="https://example.com/login" required>
                </div>
                <div class="d-flex flex-wrap gap-3 align-items-center ss-scan-actions">
                    <button type="submit" class="btn btn-cyan btn-lg px-4">Nis skanimin</button>
                    <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light btn-lg">Historiku</a>
                </div>
            </form>
        </section>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
