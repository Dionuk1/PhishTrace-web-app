<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pdo = getPDO();
$user = currentUser();

$stmt = $pdo->prepare('SELECT id, url, risk_score, status, reasons, scanned_at FROM scans WHERE user_id = :user_id ORDER BY scanned_at DESC');
$stmt->execute(['user_id' => (int) $user['id']]);
$scans = $stmt->fetchAll();

$pageTitle = t('history');
require_once __DIR__ . '/includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0"><?= e(t('history_title')); ?></h2>
    <a href="<?= e(appPath('scan.php')); ?>" class="btn btn-primary btn-sm"><?= e(t('history_new_scan')); ?></a>
</div>

<?php if (!$scans): ?>
    <div class="alert alert-info"><?= e(t('history_empty')); ?></div>
<?php else: ?>
    <div class="table-responsive">
        <table class="table table-striped align-middle">
            <thead>
            <tr>
                <th><?= e(t('history_table_date')); ?></th>
                <th><?= e(t('history_table_url')); ?></th>
                <th><?= e(t('history_table_score')); ?></th>
                <th><?= e(t('history_table_status')); ?></th>
                <th><?= e(t('history_table_reasons')); ?></th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($scans as $scan): ?>
                <?php $decodedReasons = json_decode((string) $scan['reasons'], true) ?: []; ?>
                <tr>
                    <td><?= e((string) $scan['scanned_at']); ?></td>
                    <td><small><code><?= e((string) $scan['url']); ?></code></small></td>
                    <td><?= (int) $scan['risk_score']; ?></td>
                    <td>
                        <span class="badge text-bg-<?= e(statusBadgeClass((string) $scan['status'])); ?>">
                            <?= e((string) $scan['status']); ?>
                        </span>
                    </td>
                    <td>
                        <?php if ($decodedReasons): ?>
                            <ul class="mb-0">
                                <?php foreach ($decodedReasons as $reason): ?>
                                    <li><small><?= e((string) $reason); ?></small></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <small class="text-muted"><?= e(t('history_no_reasons')); ?></small>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
