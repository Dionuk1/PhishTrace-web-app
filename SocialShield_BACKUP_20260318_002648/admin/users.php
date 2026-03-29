<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

function usersBackupDirectory(): string
{
    // Use centralized backup directory function for consistency
    require_once __DIR__ . '/../includes/functions.php';
    return ssBackupDirectory();
}

function listUserBackupCsvFiles(): array
{
    $backupDir = usersBackupDirectory();
    if (!is_dir($backupDir)) {
        return [];
    }

    $files = glob($backupDir . DIRECTORY_SEPARATOR . 'users*.csv') ?: [];
    usort($files, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
    return $files;
}

function readUsersFromBackupCsv(string $filePath): array
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

function collectMissingUsersFromBackups(array $backupFiles, array $activeEmails): array
{
    $missing = [];

    foreach ($backupFiles as $filePath) {
        $users = readUsersFromBackupCsv($filePath);
        foreach ($users as $email => $row) {
            if (isset($activeEmails[$email]) || isset($missing[$email])) {
                continue;
            }

            $missing[$email] = [
                'email' => $email,
                'name' => (string) ($row['name'] ?? ''),
                'role' => (string) ($row['role'] ?? 'user'),
                'created_at' => (string) ($row['created_at'] ?? ''),
                'backup_file' => basename($filePath),
                'backup_time' => date('Y-m-d H:i:s', (int) filemtime($filePath)),
            ];
        }
    }

    return array_values($missing);
}

function restoreUserFromBackup(PDO $pdo, string $backupFileName, string $email): bool
{
    $backupDir = usersBackupDirectory();
    $realPath = realpath($backupDir . DIRECTORY_SEPARATOR . basename($backupFileName));
    if ($realPath === false || !str_starts_with($realPath, $backupDir)) {
        return false;
    }

    $rows = readUsersFromBackupCsv($realPath);
    $email = strtolower(trim($email));
    $row = $rows[$email] ?? null;
    if (!is_array($row)) {
        return false;
    }

    $existsStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $existsStmt->execute(['email' => $email]);
    if ($existsStmt->fetch()) {
        return true;
    }

    createUsersBackup($pdo, 'before_restore_user');

    $columns = ['name', 'email', 'password_hash', 'role'];
    $params = [
        'name' => (string) ($row['name'] ?? 'Restored User'),
        'email' => $email,
        'password_hash' => (string) ($row['password_hash'] ?? password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT)),
        'role' => in_array(($row['role'] ?? 'user'), ['admin', 'user'], true) ? (string) $row['role'] : 'user',
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

    createUsersBackup($pdo, 'after_restore_user');
    return true;
}

$pdo = getPDO();
$current = currentUser();
$editUser = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('admin/users.php');
    }

    $action = (string) ($_POST['action'] ?? '');
    if ($action === 'update_name') {
        $userId = (int) ($_POST['user_id'] ?? 0);
        $name = trim((string) ($_POST['name'] ?? ''));

        if ($userId <= 0 || $name === '') {
            setFlash(tr('Valid user and name are required.', 'Kërkohet përdorues dhe emër i vlefshëm.'), 'warning');
            redirect('admin/users.php');
        }

        $updateStmt = $pdo->prepare('UPDATE users SET name = :name WHERE id = :id');
        $updateStmt->execute([
            'name' => $name,
            'id' => $userId,
        ]);
        createUsersBackup($pdo, 'admin_update_user');

        setFlash(tr('User name updated.', 'Emri i përdoruesit u përditësua.'), 'success');
        redirect('admin/users.php');
    }

    if ($action === 'restore_user') {
        $backupFile = (string) ($_POST['backup_file'] ?? '');
        $email = strtolower(trim((string) ($_POST['email'] ?? '')));

        if ($backupFile === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            setFlash(tr('Backup file and email are required for restore.', 'Për rikthim kërkohet skedari backup dhe email-i.'), 'warning');
            redirect('admin/users.php');
        }

        if (restoreUserFromBackup($pdo, $backupFile, $email)) {
            setFlash(tr('User restored from backup.', 'Përdoruesi u rikthye nga backup-i.'), 'success');
        } else {
            setFlash(tr('Could not restore that user from backup.', 'Nuk u arrit rikthimi i përdoruesit nga backup-i.'), 'danger');
        }
        redirect('admin/users.php');
    }

    if ($action === 'delete') {
        setFlash(tr('User deletion is disabled to protect registered accounts.', 'Fshirja e përdoruesve është çaktivizuar për të mbrojtur llogaritë e regjistruara.'), 'warning');
        redirect('admin/users.php');
    }
}

if (isset($_GET['edit'])) {
    $editId = (int) $_GET['edit'];
    if ($editId > 0) {
        $editStmt = $pdo->prepare('SELECT id, name, email, role FROM users WHERE id = :id LIMIT 1');
        $editStmt->execute(['id' => $editId]);
        $editUser = $editStmt->fetch() ?: null;
    }
}

$stmt = $pdo->query(
    "SELECT id, name, email, role, created_at
     FROM users
     ORDER BY created_at DESC"
);
$users = $stmt->fetchAll();
$activeEmails = [];
foreach ($users as $user) {
    $activeEmails[strtolower((string) $user['email'])] = true;
}
$backupFiles = listUserBackupCsvFiles();
$missingUsers = collectMissingUsersFromBackups($backupFiles, $activeEmails);

$pageTitle = t('admin_users');
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0"><?= e(tr('Registered Users', 'Përdoruesit e Regjistruar')); ?></h2>
    <div class="d-flex gap-2">
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/restore_users.php')); ?>">Restore Users Backup</a>
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/dashboard.php')); ?>"><?= e(tr('Back to Dashboard', 'Kthehu te Paneli')); ?></a>
    </div>
</div>

<div class="card ss-card mb-3">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
            <h3 class="h5 mb-0"><?= e(tr('User Protection and Restore', 'Mbrojtja dhe Rikthimi i Përdoruesve')); ?></h3>
            <span class="badge text-bg-info"><?= count($backupFiles); ?> <?= e(tr('backup files', 'backup-e')); ?></span>
        </div>
        <p class="text-muted mb-0"><?= e(tr('User deletion is disabled. If an account goes missing, restore it from the backup list below with one button.', 'Fshirja e përdoruesve është çaktivizuar. Nëse një llogari mungon, riktheje nga lista e backup-eve më poshtë me një buton.')); ?></p>
    </div>
</div>

<?php if ($missingUsers !== []): ?>
    <div class="card ss-card mb-3 border border-warning">
        <div class="card-body">
            <h3 class="h5 mb-3"><?= e(tr('Missing Users Found in Backups', 'Përdorues të Munguar të Gjetur në Backup')); ?></h3>
            <div class="table-responsive">
                <table class="table table-dark table-striped align-middle mb-0">
                    <thead>
                    <tr>
                        <th><?= e(t('name_label')); ?></th>
                        <th><?= e(t('email')); ?></th>
                        <th><?= e(t('role_label')); ?></th>
                        <th><?= e(tr('Backup File', 'Skedari Backup')); ?></th>
                        <th><?= e(tr('Backup Time', 'Koha e Backup-it')); ?></th>
                        <th><?= e(tr('Action', 'Veprimi')); ?></th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($missingUsers as $missingUser): ?>
                        <tr>
                            <td><?= e((string) $missingUser['name']); ?></td>
                            <td><code><?= e((string) $missingUser['email']); ?></code></td>
                            <td><?= e((string) $missingUser['role']); ?></td>
                            <td><small><?= e((string) $missingUser['backup_file']); ?></small></td>
                            <td><?= e((string) $missingUser['backup_time']); ?></td>
                            <td>
                                <form method="post" action="<?= e(appPath('admin/users.php')); ?>" class="d-inline">
                                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                    <input type="hidden" name="action" value="restore_user">
                                    <input type="hidden" name="backup_file" value="<?= e((string) $missingUser['backup_file']); ?>">
                                    <input type="hidden" name="email" value="<?= e((string) $missingUser['email']); ?>">
                                    <button type="submit" class="btn btn-sm btn-success"><?= e(tr('Restore User', 'Rikthe Përdoruesin')); ?></button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php if ($editUser): ?>
    <div class="card ss-card mb-3">
        <div class="card-body">
            <h3 class="h5 mb-3"><?= e(tr('Edit User Name', 'Ndrysho Emrin e Përdoruesit')); ?></h3>
            <form method="post" action="<?= e(appPath('admin/users.php')); ?>" class="row g-3 align-items-end">
                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                <input type="hidden" name="action" value="update_name">
                <input type="hidden" name="user_id" value="<?= (int) $editUser['id']; ?>">
                <div class="col-md-4">
                    <label class="form-label"><?= e(t('email')); ?></label>
                    <input type="text" class="form-control" value="<?= e((string) $editUser['email']); ?>" disabled>
                </div>
                <div class="col-md-4">
                    <label for="name" class="form-label"><?= e(t('name_label')); ?></label>
                    <input type="text" id="name" name="name" class="form-control" value="<?= e((string) $editUser['name']); ?>" required>
                </div>
                <div class="col-md-4 d-flex gap-2">
                    <button type="submit" class="btn btn-cyan"><?= e(tr('Save Name', 'Ruaj Emrin')); ?></button>
                    <a href="<?= e(appPath('admin/users.php')); ?>" class="btn btn-outline-light"><?= e(tr('Cancel', 'Anulo')); ?></a>
                </div>
            </form>
        </div>
    </div>
<?php endif; ?>

<div class="card ss-card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-dark table-striped align-middle mb-0">
                <thead>
                <tr>
                    <th><?= e(tr('ID', 'ID')); ?></th>
                    <th><?= e(t('name_label')); ?></th>
                    <th><?= e(t('email')); ?></th>
                    <th><?= e(t('role_label')); ?></th>
                    <th><?= e(tr('Created', 'Krijuar')); ?></th>
                    <th><?= e(tr('Action', 'Veprimi')); ?></th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?= (int) $user['id']; ?></td>
                        <td><?= e((string) $user['name']); ?></td>
                        <td><?= e((string) $user['email']); ?></td>
                        <td>
                            <span class="badge text-bg-<?= ($user['role'] === 'admin') ? 'info' : 'secondary'; ?>">
                                <?= e((string) $user['role']); ?>
                            </span>
                        </td>
                        <td><?= e((string) $user['created_at']); ?></td>
                        <td>
                            <?php if ((int) $user['id'] === (int) ($current['id'] ?? 0)): ?>
                                <span class="text-muted small"><?= e(tr('Current account', 'Llogaria aktuale')); ?></span>
                            <?php else: ?>
                                <a href="<?= e(appPath('admin/users.php')); ?>?edit=<?= (int) $user['id']; ?>" class="btn btn-sm btn-outline-info"><?= e(tr('Edit', 'Ndrysho')); ?></a>
                                <span class="btn btn-sm btn-outline-secondary disabled"><?= e(tr('Protected', 'I mbrojtur')); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>

