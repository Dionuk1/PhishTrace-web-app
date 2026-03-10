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

$pageTitle = 'Admin Dashboard';
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0">Admin Dashboard</h2>
    <a href="<?= e(appPath('admin/blacklist.php')); ?>" class="btn btn-primary btn-sm">Manage Blacklist</a>
</div>

<div class="row g-3">
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6">Users</h3>
                <p class="display-6 mb-0"><?= $totalUsers; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6">Total Scans</h3>
                <p class="display-6 mb-0"><?= $totalScans; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm border-danger">
            <div class="card-body">
                <h3 class="h6">Dangerous Scans</h3>
                <p class="display-6 mb-0 text-danger"><?= $dangerousScans; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="h6">Blacklisted Domains</h3>
                <p class="display-6 mb-0"><?= $blacklistCount; ?></p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
