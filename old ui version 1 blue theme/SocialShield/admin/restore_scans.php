<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

function scansBackupDirectory(): string
{
    return realpath(__DIR__ . '/..') . DIRECTORY_SEPARATOR . 'backups';
}

function listScanBackupCsvFiles(): array
{
    $backupDir = scansBackupDirectory();
    if (!is_dir($backupDir)) {
        return [];
    }

    $files = glob($backupDir . DIRECTORY_SEPARATOR . 'scans*.csv') ?: [];
    usort($files, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $files;
}

function readScansFromBackupCsv(string $filePath): array
{
    if (!is_file($filePath)) {
        return [];
    }

    $handle = fopen($filePath, 'rb');
    if ($handle === false) {
        return [];
    }

    $header = fgetcsv($handle);
    if (!is_array($header) || $header === []) {
        fclose($handle);
        return [];
    }

    $rows = [];
    while (($row = fgetcsv($handle)) !== false) {
        if ($row === [null] || $row === false) {
            continue;
        }

        $assoc = [];
        foreach ($header as $index => $column) {
            $assoc[(string) $column] = $row[$index] ?? null;
        }

        $id = (int) ($assoc['id'] ?? 0);
        if ($id <= 0) {
            continue;
        }

        $rows[$id] = $assoc;
    }

    fclose($handle);
    return $rows;
}

function resolveScanBackupCsvPath(string $backupFileName): ?string
{
    $backupDir = scansBackupDirectory();
    $realPath = realpath($backupDir . DIRECTORY_SEPARATOR . basename($backupFileName));
    if ($realPath === false || !str_starts_with($realPath, $backupDir)) {
        return null;
    }

    return $realPath;
}

function restoreScanRecord(PDO $pdo, array $row): bool
{
    $scanId = (int) ($row['id'] ?? 0);
    $userId = (int) ($row['user_id'] ?? 0);
    if ($scanId <= 0 || $userId <= 0 || !userExists($pdo, $userId)) {
        return false;
    }

    $existsStmt = $pdo->prepare('SELECT id FROM scans WHERE id = :id LIMIT 1');
    $existsStmt->execute(['id' => $scanId]);
    if ($existsStmt->fetch()) {
        return true;
    }

    $columns = ['id', 'user_id', 'url', 'risk_score', 'status', 'reasons'];
    $params = [
        'id' => $scanId,
        'user_id' => $userId,
        'url' => (string) ($row['url'] ?? ''),
        'risk_score' => (int) ($row['risk_score'] ?? 0),
        'status' => (string) ($row['status'] ?? 'Safe'),
        'reasons' => (string) ($row['reasons'] ?? '[]'),
    ];

    if (tableHasColumn($pdo, 'scans', 'domain') && array_key_exists('domain', $row)) {
        $columns[] = 'domain';
        $params['domain'] = (string) ($row['domain'] ?? '');
    }

    if (!empty($row['scanned_at'])) {
        $columns[] = 'scanned_at';
        $params['scanned_at'] = (string) $row['scanned_at'];
    }

    $columnSql = implode(', ', $columns);
    $valueSql = implode(', ', array_map(static fn(string $column): string => ':' . $column, $columns));
    $stmt = $pdo->prepare("INSERT INTO scans ({$columnSql}) VALUES ({$valueSql})");
    $stmt->execute($params);
    syncUserSecurityScore($pdo, $userId);
    return true;
}

$pdo = getPDO();
$backupFiles = listScanBackupCsvFiles();
$selectedBackupName = (string) ($_GET['file'] ?? ($_POST['backup_file'] ?? ($backupFiles !== [] ? basename($backupFiles[0]) : '')));
$selectedBackupPath = $selectedBackupName !== '' ? resolveScanBackupCsvPath($selectedBackupName) : null;
$backupRows = $selectedBackupPath ? readScansFromBackupCsv($selectedBackupPath) : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('admin/restore_scans.php');
    }

    $action = (string) ($_POST['action'] ?? '');
    $backupFile = (string) ($_POST['backup_file'] ?? '');
    $backupPath = resolveScanBackupCsvPath($backupFile);
    $rows = $backupPath ? readScansFromBackupCsv($backupPath) : [];

    if ($action === 'restore_scan') {
        $scanId = (int) ($_POST['scan_id'] ?? 0);
        if (!isset($rows[$scanId])) {
            setFlash('Backup entry not found for that scan.', 'danger');
            redirect('admin/restore_scans.php?file=' . rawurlencode($backupFile));
        }

        createScansBackup($pdo, 'before_restore_scan');
        if (restoreScanRecord($pdo, $rows[$scanId])) {
            createScansBackup($pdo, 'after_restore_scan');
            setFlash('Scan restored from backup.', 'success');
        } else {
            setFlash('Could not restore that scan from backup.', 'danger');
        }
        redirect('admin/restore_scans.php?file=' . rawurlencode($backupFile));
    }

    if ($action === 'restore_missing_all') {
        createScansBackup($pdo, 'before_restore_all_scans');
        $restored = 0;
        foreach ($rows as $row) {
            $scanId = (int) ($row['id'] ?? 0);
            $checkStmt = $pdo->prepare('SELECT id FROM scans WHERE id = :id LIMIT 1');
            $checkStmt->execute(['id' => $scanId]);
            if ($checkStmt->fetch()) {
                continue;
            }
            if (restoreScanRecord($pdo, $row)) {
                $restored++;
            }
        }
        createScansBackup($pdo, 'after_restore_all_scans');
        setFlash('Restored ' . $restored . ' missing scan(s) from backup.', 'success');
        redirect('admin/restore_scans.php?file=' . rawurlencode($backupFile));
    }
}

$currentScanStmt = $pdo->query('SELECT id FROM scans');
$currentScanIds = array_flip(array_map('intval', $currentScanStmt->fetchAll(PDO::FETCH_COLUMN)));

$pageTitle = 'Restore Scans Backup';
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0">Restore Scans Backup</h2>
    <div class="d-flex gap-2">
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('history.php')); ?>">View History</a>
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/dashboard.php')); ?>">Back to Dashboard</a>
    </div>
</div>

<div class="row g-3">
    <div class="col-lg-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h3 class="h5 mb-3">Available Scan Backups</h3>
                <?php if ($backupFiles === []): ?>
                    <p class="text-muted mb-0">No scan backup CSV files found.</p>
                <?php else: ?>
                    <div class="list-group">
                        <?php foreach ($backupFiles as $filePath): ?>
                            <?php $fileName = basename($filePath); ?>
                            <a href="<?= e(appPath('admin/restore_scans.php')); ?>?file=<?= e(rawurlencode($fileName)); ?>" class="list-group-item list-group-item-action <?= $selectedBackupName === $fileName ? 'active' : ''; ?>">
                                <div class="fw-semibold"><?= e($fileName); ?></div>
                                <small><?= e(date('Y-m-d H:i:s', (int) filemtime($filePath))); ?></small>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-8">
        <div class="card ss-card h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                    <div>
                        <h3 class="h5 mb-1">Backup Preview</h3>
                        <p class="text-muted mb-0"><?= $selectedBackupName !== '' ? e($selectedBackupName) : 'Select a backup file'; ?></p>
                    </div>
                    <?php if ($selectedBackupName !== '' && $backupRows !== []): ?>
                        <form method="post" action="<?= e(appPath('admin/restore_scans.php')); ?>?file=<?= e(rawurlencode($selectedBackupName)); ?>">
                            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                            <input type="hidden" name="action" value="restore_missing_all">
                            <input type="hidden" name="backup_file" value="<?= e($selectedBackupName); ?>">
                            <button type="submit" class="btn btn-success btn-sm">Restore All Missing Scans</button>
                        </form>
                    <?php endif; ?>
                </div>

                <?php if ($backupRows === []): ?>
                    <p class="text-muted mb-0">No scans found in this backup file.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>URL</th>
                                <th>Status</th>
                                <th>Scanned At</th>
                                <th>Restore</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($backupRows as $scanId => $row): ?>
                                <?php $exists = isset($currentScanIds[(int) $scanId]); ?>
                                <tr>
                                    <td><?= (int) $scanId; ?></td>
                                    <td><?= (int) ($row['user_id'] ?? 0); ?></td>
                                    <td><small><code><?= e((string) ($row['url'] ?? '')); ?></code></small></td>
                                    <td><?= e((string) ($row['status'] ?? '')); ?></td>
                                    <td><?= e((string) ($row['scanned_at'] ?? '')); ?></td>
                                    <td>
                                        <?php if ($exists): ?>
                                            <span class="btn btn-sm btn-outline-secondary disabled">Already Active</span>
                                        <?php else: ?>
                                            <form method="post" action="<?= e(appPath('admin/restore_scans.php')); ?>?file=<?= e(rawurlencode($selectedBackupName)); ?>" class="d-inline">
                                                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                                <input type="hidden" name="action" value="restore_scan">
                                                <input type="hidden" name="backup_file" value="<?= e($selectedBackupName); ?>">
                                                <input type="hidden" name="scan_id" value="<?= (int) $scanId; ?>">
                                                <button type="submit" class="btn btn-sm btn-success">Restore Scan</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
