<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

function usersBackupDirectoryRestore(): string
{
    // Use centralized backup directory function for consistency
    require_once __DIR__ . '/../includes/functions.php';
    return ssBackupDirectory();
}

function listUserBackupCsvFilesRestore(): array
{
    $backupDir = usersBackupDirectoryRestore();
    if (!is_dir($backupDir)) {
        return [];
    }

    $files = glob($backupDir . DIRECTORY_SEPARATOR . 'users*.csv') ?: [];
    usort($files, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $files;
}

function readUsersFromBackupCsvRestore(string $filePath): array
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

        $email = strtolower(trim((string) ($assoc['email'] ?? '')));
        if ($email === '') {
            continue;
        }

        $assoc['email'] = $email;
        $rows[$email] = $assoc;
    }

    fclose($handle);
    return $rows;
}

function resolveBackupCsvPath(string $backupFileName): ?string
{
    $backupDir = usersBackupDirectoryRestore();
    $realPath = realpath($backupDir . DIRECTORY_SEPARATOR . basename($backupFileName));
    if ($realPath === false || !str_starts_with($realPath, $backupDir)) {
        return null;
    }

    return $realPath;
}

function restoreUserRecord(PDO $pdo, array $row): bool
{
    $email = strtolower(trim((string) ($row['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $existsStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $existsStmt->execute(['email' => $email]);
    if ($existsStmt->fetch()) {
        return true;
    }

    $columns = ['name', 'email', 'password_hash', 'role'];
    $params = [
        'name' => (string) ($row['name'] ?? 'Restored User'),
        'email' => $email,
        'password_hash' => (string) ($row['password_hash'] ?? password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT)),
        'role' => in_array((string) ($row['role'] ?? 'user'), ['admin', 'user'], true) ? (string) $row['role'] : 'user',
    ];

    if (tableHasColumn($pdo, 'users', 'security_score')) {
        $columns[] = 'security_score';
        $params['security_score'] = (int) ($row['security_score'] ?? 0);
    }

    if (tableHasColumn($pdo, 'users', 'created_at') && !empty($row['created_at'])) {
        $columns[] = 'created_at';
        $params['created_at'] = (string) $row['created_at'];
    }

    $columnSql = implode(', ', $columns);
    $valueSql = implode(', ', array_map(static fn(string $column): string => ':' . $column, $columns));
    $stmt = $pdo->prepare("INSERT INTO users ({$columnSql}) VALUES ({$valueSql})");
    $stmt->execute($params);
    return true;
}

$pdo = getPDO();
$backupFiles = listUserBackupCsvFilesRestore();
$selectedBackupName = (string) ($_GET['file'] ?? ($_POST['backup_file'] ?? ($backupFiles !== [] ? basename($backupFiles[0]) : '')));
$selectedBackupPath = $selectedBackupName !== '' ? resolveBackupCsvPath($selectedBackupName) : null;
$backupRows = $selectedBackupPath ? readUsersFromBackupCsvRestore($selectedBackupPath) : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('admin/restore_users.php');
    }

    $action = (string) ($_POST['action'] ?? '');
    $backupFile = (string) ($_POST['backup_file'] ?? '');
    $backupPath = resolveBackupCsvPath($backupFile);
    $rows = $backupPath ? readUsersFromBackupCsvRestore($backupPath) : [];

    if ($action === 'restore_user') {
        $email = strtolower(trim((string) ($_POST['email'] ?? '')));
        if (!isset($rows[$email])) {
            setFlash('Backup entry not found for that user.', 'danger');
            redirect('admin/restore_users.php?file=' . rawurlencode($backupFile));
        }

        createUsersBackup($pdo, 'before_restore_user');
        if (restoreUserRecord($pdo, $rows[$email])) {
            createUsersBackup($pdo, 'after_restore_user');
            setFlash('User restored from backup.', 'success');
        } else {
            setFlash('Could not restore that user from backup.', 'danger');
        }
        redirect('admin/restore_users.php?file=' . rawurlencode($backupFile));
    }

    if ($action === 'restore_missing_all') {
        createUsersBackup($pdo, 'before_restore_all_users');
        $restored = 0;
        foreach ($rows as $row) {
            $email = strtolower(trim((string) ($row['email'] ?? '')));
            $checkStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $checkStmt->execute(['email' => $email]);
            if ($checkStmt->fetch()) {
                continue;
            }

            if (restoreUserRecord($pdo, $row)) {
                $restored++;
            }
        }
        createUsersBackup($pdo, 'after_restore_all_users');
        setFlash('Restored ' . $restored . ' missing user(s) from backup.', 'success');
        redirect('admin/restore_users.php?file=' . rawurlencode($backupFile));
    }
}

$currentUsersStmt = $pdo->query('SELECT email FROM users');
$currentEmails = array_flip(array_map('strtolower', array_column($currentUsersStmt->fetchAll(), 'email')));

$pageTitle = t('restore_users_backup');
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0">Restore Users Backup</h2>
    <div class="d-flex gap-2">
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/users.php')); ?>">Manage Users</a>
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/dashboard.php')); ?>">Back to Dashboard</a>
    </div>
</div>

<div class="row g-3">
    <div class="col-lg-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h3 class="h5 mb-3">Available User Backups</h3>
                <?php if ($backupFiles === []): ?>
                    <p class="text-muted mb-0">No backup CSV files found.</p>
                <?php else: ?>
                    <div class="list-group">
                        <?php foreach ($backupFiles as $filePath): ?>
                            <?php $fileName = basename($filePath); ?>
                            <a href="<?= e(appPath('admin/restore_users.php')); ?>?file=<?= e(rawurlencode($fileName)); ?>" class="list-group-item list-group-item-action <?= $selectedBackupName === $fileName ? 'active' : ''; ?>">
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
                        <form method="post" action="<?= e(appPath('admin/restore_users.php')); ?>?file=<?= e(rawurlencode($selectedBackupName)); ?>">
                            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                            <input type="hidden" name="action" value="restore_missing_all">
                            <input type="hidden" name="backup_file" value="<?= e($selectedBackupName); ?>">
                            <button type="submit" class="btn btn-success btn-sm">Restore All Missing Users</button>
                        </form>
                    <?php endif; ?>
                </div>

                <?php if ($backupRows === []): ?>
                    <p class="text-muted mb-0">No users found in this backup file.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Created</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($backupRows as $email => $row): ?>
                                <?php $exists = isset($currentEmails[$email]); ?>
                                <tr>
                                    <td><?= e((string) ($row['name'] ?? '')); ?></td>
                                    <td><code><?= e($email); ?></code></td>
                                    <td><?= e((string) ($row['role'] ?? 'user')); ?></td>
                                    <td><?= e((string) ($row['created_at'] ?? '')); ?></td>
                                    <td>
                                        <span class="badge text-bg-<?= $exists ? 'secondary' : 'success'; ?>">
                                            <?= $exists ? 'Already Active' : 'Missing / Restorable'; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($exists): ?>
                                            <span class="btn btn-sm btn-outline-secondary disabled">No Restore Needed</span>
                                        <?php else: ?>
                                            <form method="post" action="<?= e(appPath('admin/restore_users.php')); ?>?file=<?= e(rawurlencode($selectedBackupName)); ?>" class="d-inline">
                                                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                                <input type="hidden" name="action" value="restore_user">
                                                <input type="hidden" name="backup_file" value="<?= e($selectedBackupName); ?>">
                                                <input type="hidden" name="email" value="<?= e($email); ?>">
                                                <button type="submit" class="btn btn-sm btn-success">Restore User</button>
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
