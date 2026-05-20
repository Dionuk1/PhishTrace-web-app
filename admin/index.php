<?php
/**
 * ADMIN PANEL INDEX (DASHBOARD)
 * ----------------------------
 * This serves as the main entry point for administrators.
 * It provides a high-level overview of system metrics, including total users,
 * recent scans, and quick access to management tools.
 */

declare(strict_types=1);

// Include core functions for system logic and security
require_once __DIR__ . '/../includes/functions.php';

/**
 * SESSION PROTECTION
 * ------------------
 * Enforces strict access control. If the user is not authenticated as an admin,
 * they are immediately redirected to the public homepage to prevent unauthorized access.
 */
requireLogin();
requireAdmin();

// Initialize DB connection for stats retrieval
$pdo = getPDO();

/**
 * METRIC COLLECTION
 * Fetch real-time statistics from the database to populate the dashboard.
 */
// Count total registered users
$userCountStmt = $pdo->query('SELECT COUNT(*) FROM users');
$totalUsers = (int) $userCountStmt->fetchColumn();

// Count total scans performed via the platform
$scanCountStmt = $pdo->query('SELECT COUNT(*) FROM scans');
$totalScans = (int) $scanCountStmt->fetchColumn();

$scanTimestampColumn = tableHasColumn($pdo, 'scans', 'created_at')
    ? 'created_at'
    : (tableHasColumn($pdo, 'scans', 'scanned_at') ? 'scanned_at' : 'id');

// Fetch 5 most recent scans for the "Recent Activity" table
$recentScansStmt = $pdo->query(
    "SELECT s.url, s.status, s.risk_score, s.{$scanTimestampColumn} AS created_at, u.name as user_name 
     FROM scans s 
     JOIN users u ON s.user_id = u.id 
     ORDER BY s.{$scanTimestampColumn} DESC LIMIT 5"
);
$recentScans = $recentScansStmt->fetchAll();

// Page title for branding and SEO
$pageTitle = 'Administrator Dashboard';
// Include the shared top layout
require_once __DIR__ . '/../includes/header.php';
?>

<!-- ADMIN DASHBOARD INTERFACE -->
<div class="ss-page-fade-in">
    <!-- Header Section: Greeting and Status -->
    <div class="d-flex justify-content-between align-items-end mb-4">
        <div>
            <p class="ss-kicker mb-2 text-cyan">Admin Central</p>
            <h1 class="ss-title mb-0">System Overview</h1>
        </div>
        <div class="ss-chip bg-dark border-cyan text-cyan fw-bold">ADMIN MODE ACTIVE</div>
    </div>

    <!-- STATS GRID: High-level metric cards -->
    <div class="row g-4 mb-5">
        <!-- Total Users Metric -->
        <div class="col-md-6 col-lg-3">
            <div class="card ss-console-card h-100 border-start border-4 border-info">
                <div class="card-body">
                    <p class="text-secondary small text-uppercase fw-bold mb-1">Registered Users</p>
                    <h2 class="h1 mb-0"><?= $totalUsers; ?></h2>
                </div>
            </div>
        </div>

        <!-- Total Scans Metric -->
        <div class="col-md-6 col-lg-3">
            <div class="card ss-console-card h-100 border-start border-4 border-cyan">
                <div class="card-body">
                    <p class="text-secondary small text-uppercase fw-bold mb-1">Total Scans</p>
                    <h2 class="h1 mb-0"><?= $totalScans; ?></h2>
                </div>
            </div>
        </div>

        <!-- Quick Access: User Management Link -->
        <div class="col-md-6 col-lg-3">
            <a href="<?= e(appPath('admin/users.php')); ?>" class="text-decoration-none h-100 d-block">
                <div class="card ss-console-card h-100 ss-hover-translate border-start border-4 border-warning">
                    <div class="card-body d-flex flex-column justify-content-center align-items-center">
                        <span class="fs-2 mb-2">👥</span>
                        <p class="text-light fw-bold mb-0">Manage Users</p>
                    </div>
                </div>
            </a>
        </div>

        <!-- Quick Access: Scan History Link -->
        <div class="col-md-6 col-lg-3">
            <a href="<?= e(appPath('history.php')); ?>" class="text-decoration-none h-100 d-block">
                <div class="card ss-console-card h-100 ss-hover-translate border-start border-4 border-primary">
                    <div class="card-body d-flex flex-column justify-content-center align-items-center">
                        <span class="fs-2 mb-2">📜</span>
                        <p class="text-light fw-bold mb-0">Scan History</p>
                    </div>
                </div>
            </a>
        </div>
    </div>

    <!-- RECENT ACTIVITY: Detailed table of latest system events -->
    <div class="card ss-console-card shadow-lg">
        <div class="card-header bg-transparent border-secondary p-4">
            <h3 class="h5 mb-0">Recent Analysis Activity</h3>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-hover align-middle mb-0 ss-table-modern">
                    <thead class="bg-black text-secondary">
                        <tr>
                            <th class="ps-4">User</th>
                            <th>Target URL</th>
                            <th>Risk Score</th>
                            <th>Status</th>
                            <th class="pe-4 text-end">Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($recentScans): ?>
                            <?php foreach ($recentScans as $scan): ?>
                                <?php $tone = riskBarTone($scan['status']); ?>
                                <tr>
                                    <td class="ps-4 fw-bold text-info"><?= e((string) $scan['user_name']); ?></td>
                                    <td><code class="text-secondary small"><?= e(substr((string) $scan['url'], 0, 50)); ?>...</code></td>
                                    <td>
                                        <span class="fw-bold text-<?= $tone; ?>"><?= (int) $scan['risk_score']; ?>%</span>
                                    </td>
                                    <td>
                                        <span class="ss-status-pill ss-status-pill--<?= $tone; ?> small py-1"><?= e((string) $scan['status']); ?></span>
                                    </td>
                                    <td class="pe-4 text-end text-secondary small"><?= e(date('M j, H:i', strtotime((string) $scan['created_at']))); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <!-- Empty State -->
                            <tr>
                                <td colspan="5" class="text-center py-5 text-secondary italic">No recent scans recorded.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Link to full history -->
        <div class="card-footer bg-transparent border-top border-secondary text-center py-3">
            <a href="<?= e(appPath('history.php')); ?>" class="text-cyan text-decoration-none small fw-bold">View Comprehensive Audit Log &rarr;</a>
        </div>
    </div>
</div>

<?php 
// Include shared footer layout
require_once __DIR__ . '/../includes/footer.php'; 
?>
