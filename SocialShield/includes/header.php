<?php
// Shared top layout and navigation.

declare(strict_types=1);

require_once __DIR__ . '/functions.php';

$flash = getFlash();
$user = currentUser();
$pageTitle = $pageTitle ?? 'SocialShield';
$achievementNotifications = [
    'latest_unlock' => null,
    'total_achievements' => 0,
    'total_points' => 0,
    'achievements' => [],
];

if ($user) {
    $achievementNotifications = getUserAchievementNotificationData((int) $user['id'], getPDO());
}

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($pageTitle); ?> | SocialShield</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="<?= e(appPath('assets/css/style.css')); ?>" rel="stylesheet">
</head>
<body class="ss-body">
<nav class="navbar navbar-expand-lg navbar-dark ss-navbar">
    <div class="container">
        <a class="navbar-brand fw-bold" href="<?= e(appPath('index.php')); ?>">SocialShield</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarMain">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarMain">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('index.php')); ?>">Home</a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('scan.php')); ?>">Scan URL</a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('history.php')); ?>">History</a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('tips.php')); ?>">Security Tips</a></li>
                <?php if ($user && $user['role'] === 'admin'): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="<?= e(appPath('admin/dashboard.php')); ?>">Admin</a>
                    </li>
                <?php endif; ?>
            </ul>
            <ul class="navbar-nav align-items-lg-center gap-lg-2">
                <?php if ($user): ?>
                    <li class="nav-item dropdown">
                        <button
                            class="btn ss-notification-btn dropdown-toggle"
                            type="button"
                            data-bs-toggle="dropdown"
                            data-bs-auto-close="outside"
                            aria-expanded="false"
                            aria-label="Achievement notifications">
                            <span class="ss-notification-btn__icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" focusable="false">
                                    <path d="M12 3a4 4 0 0 0-4 4v1.2c0 .7-.2 1.4-.6 2L6 12.5V15h12v-2.5l-1.4-3.3a4.8 4.8 0 0 1-.6-2V7a4 4 0 0 0-4-4Zm0 18a2.8 2.8 0 0 1-2.6-2h5.2A2.8 2.8 0 0 1 12 21Z"></path>
                                </svg>
                            </span>
                            <span class="ss-notification-btn__label">Notifications</span>
                            <span class="ss-notification-badge"><?= (int) $achievementNotifications['total_achievements']; ?></span>
                        </button>
                        <div class="dropdown-menu dropdown-menu-end ss-notification-menu p-0">
                            <div class="ss-notification-menu__header">
                                <span class="ss-metric-label mb-1">Achievement unlocked</span>
                                <?php if ($achievementNotifications['latest_unlock']): ?>
                                    <strong><?= e((string) $achievementNotifications['latest_unlock']['title']); ?></strong>
                                    <small><?= e((string) $achievementNotifications['latest_unlock']['description']); ?></small>
                                <?php else: ?>
                                    <strong>No achievements yet</strong>
                                    <small>Your unlocked achievements will show here.</small>
                                <?php endif; ?>
                            </div>
                            <div class="ss-notification-menu__stats">
                                <div>
                                    <span class="ss-metric-label mb-1">Total achievements</span>
                                    <strong><?= (int) $achievementNotifications['total_achievements']; ?></strong>
                                </div>
                                <div>
                                    <span class="ss-metric-label mb-1">Total points</span>
                                    <strong><?= (int) $achievementNotifications['total_points']; ?></strong>
                                </div>
                            </div>
                            <div class="ss-notification-menu__list">
                                <?php if ($achievementNotifications['achievements'] === []): ?>
                                    <div class="ss-notification-empty">Complete scans to unlock achievements and earn points.</div>
                                <?php else: ?>
                                    <?php foreach ($achievementNotifications['achievements'] as $achievement): ?>
                                        <div class="ss-notification-item">
                                            <div class="ss-notification-item__main">
                                                <strong><?= e((string) $achievement['title']); ?></strong>
                                                <small><?= e((string) $achievement['description']); ?></small>
                                            </div>
                                            <div class="ss-notification-item__meta">
                                                <span>+<?= (int) $achievement['points']; ?> pts</span>
                                                <small><?= e(date('M j', strtotime((string) $achievement['unlocked_at']))); ?></small>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </li>
                    <li class="nav-item"><span class="nav-link">Hi, <?= e($user['name']); ?></span></li>
                    <li class="nav-item"><a class="nav-link" href="<?= e(appPath('logout.php')); ?>">Logout</a></li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link" href="<?= e(appPath('login.php')); ?>">Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="<?= e(appPath('register.php')); ?>">Register</a></li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<main class="container py-4">
    <?php if ($flash): ?>
        <div class="alert alert-<?= e($flash['type']); ?> alert-dismissible fade show" role="alert">
            <?= e($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>
