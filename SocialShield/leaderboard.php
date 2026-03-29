<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

$pdo = getPDO();
$rows = $pdo->query(
    "SELECT
        u.name,
        COALESCE(SUM(
            CASE
                WHEN s.status = 'Safe' THEN 10
                WHEN s.status = 'Suspicious' THEN 3
                WHEN s.status = 'Dangerous' THEN 1
                ELSE 0
            END
        ), 0) AS security_score
     FROM users u
     LEFT JOIN scans s ON s.user_id = u.id
     GROUP BY u.id, u.name, u.created_at
     ORDER BY security_score DESC, u.created_at ASC
     LIMIT 20"
)->fetchAll();

$pageTitle = t('leaderboard');
require_once __DIR__ . '/includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0"><?= e(tr('Cyber Awareness Leaderboard', 'Klasifikimi i Vetëdijes Kibernetike')); ?></h2>
</div>

<div class="card ss-card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-dark table-striped align-middle mb-0">
                <thead>
                <tr>
                    <th>#</th>
                    <th><?= e(tr('User', 'Përdoruesi')); ?></th>
                    <th><?= e(tr('Security Score', 'Pikët e Sigurisë')); ?></th>
                    <th><?= e(tr('Level', 'Niveli')); ?></th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($rows as $index => $row): ?>
                    <?php $score = (int) ($row['security_score'] ?? 0); ?>
                    <tr>
                        <td><?= $index + 1; ?></td>
                        <td><?= e((string) $row['name']); ?></td>
                        <td><?= $score; ?></td>
                        <td><?= e(securityLevelFromScore($score)); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
