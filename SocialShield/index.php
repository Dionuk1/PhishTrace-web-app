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
                    <h1 class="display-5 fw-bold"><?= e(t('hero_title')); ?></h1>
                    <p class="fs-5 ss-hero-copy">
                        <?= e(t('hero_subtitle')); ?>
                    </p>
                    <div class="d-flex gap-3 flex-wrap ss-hero-actions">
                        <a href="<?= e(appPath('scan.php')); ?>" class="btn ss-btn-hero-primary btn-lg"><?= e(t('scan_cta')); ?></a>
                        <a href="<?= e(appPath('tips.php')); ?>" class="btn ss-btn-hero-secondary btn-lg"><?= e(t('tips_cta')); ?></a>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                <aside class="ss-hero-side h-100" aria-label="<?= e(t('quick_checks')); ?>">
                    <p class="ss-kicker mb-3"><?= e(t('quick_checks')); ?></p>
                    <div class="ss-hero-tip-list">
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">2FA</span>
                            <div>
                                <h3 class="h6 mb-1"><?= e(t('tip_2fa_title')); ?></h3>
                                <p class="mb-0"><?= e(t('tip_2fa_desc')); ?></p>
                            </div>
                        </div>
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">LINK</span>
                            <div>
                                <h3 class="h6 mb-1"><?= e(t('tip_link_title')); ?></h3>
                                <p class="mb-0"><?= e(t('tip_link_desc')); ?></p>
                            </div>
                        </div>
                        <div class="ss-hero-tip-card">
                            <span class="ss-hero-tip-icon">PASS</span>
                            <div>
                                <h3 class="h6 mb-1"><?= e(t('tip_pass_title')); ?></h3>
                                <p class="mb-0"><?= e(t('tip_pass_desc')); ?></p>
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
                <h5 class="card-title"><?= e(t('step_1_title')); ?></h5>
                <p class="card-text"><?= e(t('step_1_desc')); ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100 shadow-sm">
            <div class="card-body">
                <h5 class="card-title"><?= e(t('step_2_title')); ?></h5>
                <p class="card-text"><?= e(t('step_2_desc')); ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card h-100 shadow-sm">
            <div class="card-body">
                <h5 class="card-title"><?= e(t('step_3_title')); ?></h5>
                <p class="card-text"><?= e(t('step_3_desc')); ?></p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

