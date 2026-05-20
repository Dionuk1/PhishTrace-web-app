<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../api/honeypot/HoneypotJsonStorage.php';
requireLogin();
requireAdmin();

$pageTitle = 'Honeypot Dashboard';
$storage = new HoneypotJsonStorage(__DIR__ . '/../data');
$messages = array_reverse($storage->getAllMessages());

$riskFilter = strtoupper(trim((string) ($_GET['risk'] ?? '')));
$usernameSearch = trim((string) ($_GET['username'] ?? ''));
$urlsOnly = isset($_GET['urls_only']);

$filteredMessages = array_values(array_filter($messages, function (array $message) use ($riskFilter, $usernameSearch, $urlsOnly): bool {
    $riskLevel = strtoupper((string) ($message['risk_level'] ?? 'LOW'));
    $username = strtolower((string) ($message['username'] ?? ''));
    $urls = $message['extracted_urls'] ?? [];

    if ($riskFilter !== '' && $riskLevel !== $riskFilter) {
        return false;
    }

    if ($usernameSearch !== '' && strpos($username, strtolower($usernameSearch)) === false) {
        return false;
    }

    if ($urlsOnly && count($urls) === 0) {
        return false;
    }

    return true;
}));

$totalUrls = 0;
$highRiskMessages = 0;
foreach ($messages as $message) {
    $totalUrls += count($message['extracted_urls'] ?? []);
    if (strtoupper((string) ($message['risk_level'] ?? 'LOW')) === 'HIGH') {
        $highRiskMessages++;
    }
}

require_once __DIR__ . '/../includes/header.php';
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="h4 fw-bold mb-1">Social Media Honeypot Dashboard</h1>
            <p class="text-muted mb-0">Suspicious message and phishing detection logs.</p>
        </div>
        <a class="btn btn-success" href="<?= e(appPath('api/honeypot/export_pdf.php')); ?>">Export PDF Report</a>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">Total Messages</div><div class="display-6"><?= count($messages); ?></div></div></div>
        </div>
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">Total URLs</div><div class="display-6"><?= $totalUrls; ?></div></div></div>
        </div>
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">HIGH Risk Messages</div><div class="display-6 text-danger"><?= $highRiskMessages; ?></div></div></div>
        </div>
    </div>

    <div class="card ss-card mb-4">
        <div class="card-body">
            <form class="row g-3" method="GET">
                <div class="col-md-3">
                    <label class="form-label">Risk Level</label>
                    <select class="form-select" name="risk">
                        <option value="">All</option>
                        <?php foreach (['LOW', 'MEDIUM', 'HIGH'] as $level): ?>
                            <option value="<?= e($level); ?>" <?= $riskFilter === $level ? 'selected' : ''; ?>><?= e($level); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Username</label>
                    <input class="form-control" type="search" name="username" value="<?= e($usernameSearch); ?>" placeholder="Search username">
                </div>
                <div class="col-md-3 d-flex align-items-end">
                    <div class="form-check mb-2">
                        <input class="form-check-input" type="checkbox" id="urlsOnly" name="urls_only" value="1" <?= $urlsOnly ? 'checked' : ''; ?>>
                        <label class="form-check-label" for="urlsOnly">Messages with URLs only</label>
                    </div>
                </div>
                <div class="col-md-2 d-flex align-items-end">
                    <button class="btn btn-primary w-100" type="submit">Filter</button>
                </div>
            </form>
        </div>
    </div>

    <div class="card ss-card">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Message</th>
                        <th>Keywords</th>
                        <th>URLs</th>
                        <th>Risk</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (!$filteredMessages): ?>
                        <tr><td colspan="7" class="text-center text-muted py-4">No messages found.</td></tr>
                    <?php endif; ?>

                    <?php foreach ($filteredMessages as $message): ?>
                        <?php
                        $riskLevel = strtoupper((string) ($message['risk_level'] ?? 'LOW'));
                        $rowClass = $riskLevel === 'HIGH' ? 'table-danger' : '';
                        $badgeClass = $riskLevel === 'HIGH' ? 'bg-danger' : ($riskLevel === 'MEDIUM' ? 'bg-warning text-dark' : 'bg-success');
                        ?>
                        <tr class="<?= e($rowClass); ?>">
                            <td>#<?= (int) ($message['id'] ?? 0); ?></td>
                            <td><strong><?= e((string) ($message['username'] ?? 'Unknown')); ?></strong></td>
                            <td style="max-width: 360px;"><?= e((string) ($message['message'] ?? '')); ?></td>
                            <td><?= e(implode(', ', $message['detected_keywords'] ?? [])); ?></td>
                            <td>
                                <?php foreach (($message['extracted_urls'] ?? []) as $url): ?>
                                    <div><small class="text-break"><?= e((string) $url); ?></small></div>
                                <?php endforeach; ?>
                            </td>
                            <td><span class="badge <?= e($badgeClass); ?>"><?= $riskLevel === 'HIGH' ? 'HIGH RISK' : e($riskLevel); ?> (<?= (int) ($message['risk_score'] ?? 0); ?>)</span></td>
                            <td><small><?= e((string) ($message['timestamp'] ?? '')); ?></small></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<style>
    .ss-card {
        border: 1px solid #e0e0e0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
</style>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
