<?php
// Shared top layout and navigation.

declare(strict_types=1);

require_once __DIR__ . '/functions.php';

if (isset($_GET['lang'])) {
    $lang = strtolower(trim((string) $_GET['lang']));
    if (in_array($lang, ['en', 'sq'], true)) {
        $_SESSION['lang'] = $lang;
    }

    if (!headers_sent()) {
        $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
        header('Location: ' . $path);
        exit;
    }
}

$flash = getFlash();
$user = currentUser();
$pageTitle = $pageTitle ?? 'PhishTrace';
$sessionLang = (string) ($_SESSION['lang'] ?? 'en');
$selectedLang = in_array($sessionLang, ['en', 'sq'], true) ? $sessionLang : 'en';
$txt = static fn(string $en, string $sq): string => $selectedLang === 'sq' ? $sq : $en;
$achievementNotifications = [
    'latest_unlock' => null,
    'total_achievements' => 0,
    'total_points' => 0,
    'achievements' => [],
];
$userCyberScore = 0;

if ($user) {
    $pdo = getPDO();
    $achievementNotifications = getUserAchievementNotificationData((int) $user['id'], $pdo);
    if (tableHasColumn($pdo, 'users', 'security_score')) {
        $scoreStmt = $pdo->prepare('SELECT COALESCE(security_score, 0) FROM users WHERE id = :id LIMIT 1');
        $scoreStmt->execute(['id' => (int) $user['id']]);
        $userCyberScore = (int) ($scoreStmt->fetchColumn() ?: 0);
    }
}

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
?>
<!doctype html>
<html lang="<?= e($selectedLang); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($pageTitle); ?> | PhishTrace</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="<?= e(appPath('assets/css/style.css')); ?>" rel="stylesheet">
</head>
<body class="ss-body">
<nav class="navbar navbar-expand-lg navbar-dark ss-navbar">
    <div class="container">
        <a class="navbar-brand fw-bold" href="<?= e(appPath('index.php')); ?>">PhishTrace</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarMain">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarMain">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0 ss-main-nav">
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('index.php')); ?>"><?= e($txt('Home', 'Ballina')); ?></a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('scan.php')); ?>"><?= e($txt('Scan URL', 'Skano URL')); ?></a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('history.php')); ?>"><?= e($txt('History', 'Historiku')); ?></a></li>
                <li class="nav-item"><a class="nav-link" href="<?= e(appPath('tips.php')); ?>"><?= e($txt('Security Tips', 'Keshilla')); ?></a></li>
                <?php if ($user && (($user['role'] ?? '') === 'admin')): ?>
                    <li class="nav-item"><a class="nav-link" href="<?= e(appPath('admin/dashboard.php')); ?>">Admin Dashboard</a></li>
                <?php endif; ?>
            </ul>

            <div class="ss-navbar-tools ms-lg-auto">
                <div class="ss-lang-switch" aria-label="Language switcher">
                    <a href="<?= e(appPath('settings.php?lang=en')); ?>" class="btn ss-lang-btn <?= $selectedLang === 'en' ? 'ss-lang-btn--active' : ''; ?>">
                        <img class="ss-lang-flag" src="https://flagcdn.com/w40/us.png" alt="US flag" loading="lazy">
                        Anglisht
                    </a>
                    <a href="<?= e(appPath('settings.php?lang=sq')); ?>" class="btn ss-lang-btn <?= $selectedLang === 'sq' ? 'ss-lang-btn--active' : ''; ?>">
                        <img class="ss-lang-flag" src="https://flagcdn.com/w40/xk.png" alt="Kosovo flag" loading="lazy">
                        Shqip
                    </a>
                </div>

                <?php if ($user): ?>
                    <div class="dropdown">
                        <button class="btn ss-notification-btn ss-notification-btn--icon dropdown-toggle" type="button" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false" aria-label="Achievement notifications">
                            <span class="ss-notification-btn__icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" focusable="false">
                                    <path d="M12 3a4 4 0 0 0-4 4v1.2c0 .7-.2 1.4-.6 2L6 12.5V15h12v-2.5l-1.4-3.3a4.8 4.8 0 0 1-.6-2V7a4 4 0 0 0-4-4Zm0 18a2.8 2.8 0 0 1-2.6-2h5.2A2.8 2.8 0 0 1 12 21Z"></path>
                                </svg>
                            </span>
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
                    </div>

                    <a class="btn ss-cyber-pill" href="<?= e(appPath('cyber_level.php')); ?>" title="Your Cyber Level">
                        <span class="ss-cyber-pill__label"><?= e(tr('Your Cyber Level', 'Niveli Yt Kibernetik')); ?></span>
                        <strong><?= (int) $userCyberScore; ?></strong>
                    </a>

                    <div class="dropdown">
                        <button class="btn ss-profile-toggle dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <?= e((string) $user['name']); ?>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end ss-profile-menu">
                            <li><a class="dropdown-item" href="<?= e(appPath('profile.php')); ?>">Profili</a></li>
                            <li><a class="dropdown-item" href="<?= e(appPath('settings.php')); ?>">Cilesimet</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="<?= e(appPath('logout.php')); ?>">Dil</a></li>
                        </ul>
                    </div>
                <?php else: ?>
                    <a class="nav-link" href="<?= e(appPath('login.php')); ?>">Login</a>
                    <a class="nav-link" href="<?= e(appPath('register.php')); ?>">Register</a>
                <?php endif; ?>
            </div>
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
