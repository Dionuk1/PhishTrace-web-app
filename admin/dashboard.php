<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

$pdo = getPDO();

$totalUsers = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
$totalScans = (int) $pdo->query('SELECT COUNT(*) FROM scans')->fetchColumn();
$dangerousScans = (int) $pdo->query("SELECT COUNT(*) FROM scans WHERE status = 'Dangerous'")->fetchColumn();
$blacklistCount = (int) $pdo->query('SELECT COUNT(*) FROM blacklist_domains')->fetchColumn();

$pageTitle = t('admin_dashboard');
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0"><?= e(t('admin_dashboard')); ?></h2>
    <div class="d-flex flex-wrap gap-2">
        <a href="<?= e(appPath('admin/blacklist.php')); ?>" class="btn btn-primary btn-sm"><?= e(t('manage_blacklist')); ?></a>
        <a href="<?= e(appPath('admin/threat_intel.php')); ?>" class="btn btn-outline-info btn-sm">OpenPhish Threat Intel</a>
    </div>
</div>

<div class="row g-3 mb-3">
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6"><?= e(t('users')); ?></h3>
                <p class="display-6 mb-0"><?= $totalUsers; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6"><?= e(t('total_scans')); ?></h3>
                <p class="display-6 mb-0"><?= $totalScans; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm border-danger">
            <div class="card-body">
                <h3 class="h6"><?= e(t('dangerous_detected')); ?></h3>
                <p class="display-6 mb-0 text-danger"><?= $dangerousScans; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6"><?= e(t('blacklisted_domains')); ?></h3>
                <p class="display-6 mb-0"><?= $blacklistCount; ?></p>
            </div>
        </div>
    </div>
</div>

<div class="card ss-card mb-3">
    <div class="card-body">
        <h3 class="h5 mb-3"><?= e(t('legacy_admin_tools')); ?></h3>
        <div class="d-flex flex-wrap gap-2">
            <a href="<?= e(appPath('admin/users.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">🛡</span><span>Protected Users Database</span></a>
            <a href="<?= e(appPath('admin/restore_users.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">♻</span><span>Restore Users</span></a>
            <a href="<?= e(appPath('admin/restore_scans.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">🔄</span><span>Restore Scans</span></a>
            <a href="<?= e(appPath('leaderboard.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">🏆</span><span>Leaderboard</span></a>
            <a href="<?= e(appPath('cyber_level.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">🎯</span><span>Cyber Level</span></a>
        </div>
    </div>
</div>

<!-- Honeypot navigation block: added separately below legacy tools. -->
<div class="card ss-card mb-3">
    <div class="card-body">
        <h3 class="h5 mb-3"><?= e(t('honeypot_dashboard')); ?></h3>
        <div class="d-flex flex-wrap gap-2">
            <a href="<?= e(appPath('honeypot_demo.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">📨</span><span><?= e(t('demo_input_page')); ?></span></a>
            <a href="<?= e(appPath('admin/honeypot_dashboard.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">📊</span><span><?= e(t('honeypot_dashboard')); ?></span></a>
            <a href="<?= e(appPath('admin/fake_profiles.php')); ?>" class="btn btn-outline-light btn-sm ss-tool-btn"><span class="ss-tool-btn__icon" aria-hidden="true">👤</span><span><?= e(t('fake_profile_system')); ?></span></a>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
