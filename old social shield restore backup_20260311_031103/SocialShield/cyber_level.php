<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pdo = getPDO();
$user = currentUser();
$userId = (int) ($user['id'] ?? 0);
$hasSecurityScore = tableHasColumn($pdo, 'users', 'security_score');

// Refresh latest user score from DB.
$selectScore = $hasSecurityScore ? 'security_score' : '0 AS security_score';
$stmt = $pdo->prepare("SELECT name, {$selectScore} FROM users WHERE id = :id LIMIT 1");
$stmt->execute(['id' => $userId]);
$row = $stmt->fetch() ?: ['name' => $user['name'] ?? 'User', 'security_score' => 0];

$securityScore = syncUserSecurityScore($pdo, $userId);
$level = securityLevelFromScore($securityScore);

$statsStmt = $pdo->prepare(
    "SELECT
        COUNT(*) AS total_scans,
        SUM(CASE WHEN status = 'Safe' THEN 1 ELSE 0 END) AS safe_scans,
        SUM(CASE WHEN status = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_scans,
        SUM(CASE WHEN status = 'Dangerous' THEN 1 ELSE 0 END) AS dangerous_scans
     FROM scans
     WHERE user_id = :user_id"
);
$statsStmt->execute(['user_id' => $userId]);
$stats = $statsStmt->fetch() ?: [
    'total_scans' => 0,
    'safe_scans' => 0,
    'suspicious_scans' => 0,
    'dangerous_scans' => 0,
];

$safeScans = (int) ($stats['safe_scans'] ?? 0);
$suspiciousScans = (int) ($stats['suspicious_scans'] ?? 0);
$dangerousScans = (int) ($stats['dangerous_scans'] ?? 0);
$totalScans = (int) ($stats['total_scans'] ?? 0);

$currentLevelMin = 0;
$nextLevelMin = 50;
$nextLevelName = tr('Aware User', 'PÃ«rdorues i VetÃ«dijshÃ«m');

if ($securityScore <= 50) {
    $currentLevelMin = 0;
    $nextLevelMin = 51;
    $nextLevelName = tr('Aware User', 'PÃ«rdorues i VetÃ«dijshÃ«m');
} elseif ($securityScore <= 150) {
    $currentLevelMin = 51;
    $nextLevelMin = 151;
    $nextLevelName = tr('Security Savvy', 'I Zoti nÃ« Siguri');
} elseif ($securityScore <= 300) {
    $currentLevelMin = 151;
    $nextLevelMin = 301;
    $nextLevelName = tr('Phishing Hunter', 'Gjuetar i Phishing');
} else {
    $currentLevelMin = 301;
    $nextLevelMin = 301;
    $nextLevelName = tr('Max Level Reached', 'Niveli maksimal i arritur');
}

$levelSpan = max(1, $nextLevelMin - $currentLevelMin);
$levelProgress = $securityScore >= $nextLevelMin
    ? 100
    : (int) max(0, min(100, (($securityScore - $currentLevelMin) / $levelSpan) * 100));
$pointsToNext = max(0, $nextLevelMin - $securityScore);

$safePercent = $totalScans > 0 ? (int) round(($safeScans / $totalScans) * 100) : 0;
$suspiciousPercent = $totalScans > 0 ? (int) round(($suspiciousScans / $totalScans) * 100) : 0;
$dangerousPercent = $totalScans > 0 ? (int) round(($dangerousScans / $totalScans) * 100) : 0;

if ($totalScans > 0) {
    $fix = 100 - ($safePercent + $suspiciousPercent + $dangerousPercent);
    $dangerousPercent += $fix;
}

$pageTitle = t('my_security_level');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row g-4">
    <div class="col-lg-8">
        <div class="card ss-card">
            <div class="card-body">
                <h2 class="h4 mb-3"><?= e(t('cyber_level_title')); ?></h2>
                <p><strong><?= e(t('user')); ?>:</strong> <?= e((string) $row['name']); ?></p>
                <p><strong><?= e(t('security_score')); ?>:</strong> <?= $securityScore; ?></p>
                <p><strong><?= e(t('user_level')); ?>:</strong> <?= e($level); ?></p>

                <hr>
                <h3 class="h6 mb-2"><?= e(t('score_progress')); ?></h3>
                <div class="d-flex justify-content-between small text-muted mb-2">
                    <span><?= e(t('current')); ?>: <?= e($level); ?></span>
                    <span><?= e($nextLevelName); ?></span>
                </div>
                <div class="ss-meter mb-2">
                    <div class="progress-bar bg-info" role="progressbar" style="width: <?= $levelProgress; ?>%" aria-valuenow="<?= $levelProgress; ?>" aria-valuemin="0" aria-valuemax="100"></div>
                </div>
                <?php if ($pointsToNext > 0): ?>
                    <p class="small text-muted mb-0"><?= $pointsToNext; ?> <?= e(tr('point(s) to reach', 'pikÃ« pÃ«r tÃ« arritur')); ?> <?= e($nextLevelName); ?>.</p>
                <?php else: ?>
                    <p class="small text-success mb-0"><?= e(tr('You reached the top level.', 'Ke arritur nivelin mÃ« tÃ« lartÃ«.')); ?></p>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <div class="col-lg-4">
        <div class="card ss-card">
            <div class="card-body">
                <h3 class="h5 mb-3"><?= e(t('scan_stats')); ?></h3>
                <p class="mb-2"><strong><?= e(t('total_scans')); ?>:</strong> <?= $totalScans; ?></p>
                <p class="mb-2"><strong><?= e(t('safe_detected')); ?>:</strong> <?= $safeScans; ?></p>
                <p class="mb-2"><strong><?= e(t('suspicious_detected')); ?>:</strong> <?= $suspiciousScans; ?></p>
                <p class="mb-3"><strong><?= e(t('dangerous_detected')); ?>:</strong> <?= $dangerousScans; ?></p>

                <h4 class="h6 mb-2"><?= e(t('scan_mix')); ?></h4>
                <div class="progress mb-2" style="height: 16px;">
                    <div class="progress-bar bg-success" role="progressbar" style="width: <?= $safePercent; ?>%" aria-valuenow="<?= $safePercent; ?>" aria-valuemin="0" aria-valuemax="100"></div>
                    <div class="progress-bar bg-warning" role="progressbar" style="width: <?= $suspiciousPercent; ?>%" aria-valuenow="<?= $suspiciousPercent; ?>" aria-valuemin="0" aria-valuemax="100"></div>
                    <div class="progress-bar bg-danger" role="progressbar" style="width: <?= $dangerousPercent; ?>%" aria-valuenow="<?= $dangerousPercent; ?>" aria-valuemin="0" aria-valuemax="100"></div>
                </div>
                <div class="small">
                    <span class="badge text-bg-success me-1"><?= e(tr('Safe', 'Sigurt')); ?> <?= $safePercent; ?>%</span>
                    <span class="badge text-bg-warning me-1"><?= e(tr('Suspicious', 'DyshimtÃ«')); ?> <?= $suspiciousPercent; ?>%</span>
                    <span class="badge text-bg-danger"><?= e(tr('Dangerous', 'RrezikshÃ«m')); ?> <?= $dangerousPercent; ?>%</span>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

