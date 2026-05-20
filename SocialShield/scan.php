<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pageTitle = t('scan_url');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center ss-scan-stage">
    <div class="col-xl-9 col-lg-10">
        <section class="ss-panel ss-panel-hero ss-scan-card">
            <div class="ss-scan-card__glow" aria-hidden="true"></div>
            <div class="ss-scan-intro">
                <h1 class="ss-title mb-3"><?= e(t('scan_title')); ?></h1>
                <p class="ss-lead mb-4"><?= e(t('scan_lead')); ?></p>
            </div>

            <form action="<?= e(appPath('result.php')); ?>" method="post" novalidate>
                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                <div class="mb-4">
                    <label for="url" class="form-label ss-scan-label"><?= e(t('url_label')); ?></label>
                    <input type="url" class="form-control form-control-lg ss-input ss-scan-input" id="url" name="url" placeholder="<?= e(t('url_placeholder')); ?>" required>
                </div>
                <div class="d-flex flex-wrap gap-3 align-items-center ss-scan-actions">
                    <button type="submit" class="btn ss-scan-submit btn-lg px-4"><?= e(t('start_scan')); ?></button>
                    <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light btn-lg"><?= e(t('view_history')); ?></a>
                </div>
            </form>
        </section>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
