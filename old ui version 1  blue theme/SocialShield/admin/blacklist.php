<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

$pdo = getPDO();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token.', 'danger');
        redirect('admin/blacklist.php');
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $domain = normalizeDomain((string) ($_POST['domain'] ?? ''));
        $reason = trim((string) ($_POST['reason'] ?? ''));
        $source = trim((string) ($_POST['source'] ?? 'Manual'));

        if ($domain === '' || !preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $domain)) {
            setFlash('Please enter a valid domain (example: bad-domain.com).', 'warning');
            redirect('admin/blacklist.php');
        }

        $stmt = $pdo->prepare(
            'INSERT INTO blacklist_domains (domain, reason, source) VALUES (:domain, :reason, :source)
             ON DUPLICATE KEY UPDATE reason = VALUES(reason), source = VALUES(source)'
        );
        $stmt->execute([
            'domain' => $domain,
            'reason' => $reason,
            'source' => $source,
        ]);
        setFlash('Blacklist domain saved.', 'success');
        redirect('admin/blacklist.php');
    }

    if ($action === 'delete') {
        $id = (int) ($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare('DELETE FROM blacklist_domains WHERE id = :id');
            $stmt->execute(['id' => $id]);
            setFlash('Domain removed from blacklist.', 'info');
        }
        redirect('admin/blacklist.php');
    }
}

$stmt = $pdo->query('SELECT id, domain, reason, source, created_at FROM blacklist_domains ORDER BY created_at DESC');
$domains = $stmt->fetchAll();

$pageTitle = 'Blacklist Manager';
require_once __DIR__ . '/../includes/header.php';
?>

<div class="row g-4">
    <div class="col-lg-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <h2 class="h5">Add or update blacklist domain</h2>
                <form method="post" action="<?= e(appPath('admin/blacklist.php')); ?>">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <input type="hidden" name="action" value="add">
                    <div class="mb-3">
                        <label for="domain" class="form-label">Domain</label>
                        <input type="text" id="domain" name="domain" class="form-control" placeholder="example-phish.com" required>
                        <div class="form-text">Enter domain only, not full URL.</div>
                    </div>
                    <div class="mb-3">
                        <label for="reason" class="form-label">Reason</label>
                        <input type="text" id="reason" name="reason" class="form-control" placeholder="Credential theft campaign">
                    </div>
                    <div class="mb-3">
                        <label for="source" class="form-label">Source</label>
                        <input type="text" id="source" name="source" class="form-control" value="Manual">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Save Domain</button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-lg-8">
        <div class="card shadow-sm">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h2 class="h5 mb-0">Current blacklist domains</h2>
                    <a href="<?= e(appPath('admin/dashboard.php')); ?>" class="btn btn-outline-secondary btn-sm">Back to Dashboard</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped align-middle">
                        <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Reason</th>
                            <th>Source</th>
                            <th>Added</th>
                            <th>Action</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($domains as $domain): ?>
                            <tr>
                                <td><code><?= e((string) $domain['domain']); ?></code></td>
                                <td><?= e((string) $domain['reason']); ?></td>
                                <td><?= e((string) $domain['source']); ?></td>
                                <td><?= e((string) $domain['created_at']); ?></td>
                                <td>
                                    <form method="post" action="<?= e(appPath('admin/blacklist.php')); ?>" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="id" value="<?= (int) $domain['id']; ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger js-confirm-delete">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
