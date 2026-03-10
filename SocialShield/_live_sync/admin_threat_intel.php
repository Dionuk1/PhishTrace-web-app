<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

$pdo = getPDO();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token. Please try again.', 'danger');
        redirect('admin/threat_intel.php');
    }

    $action = trim((string) ($_POST['action'] ?? ''));
    if ($action === 'run_agent') {
        require_once __DIR__ . '/../agents/agent_update.php';
        $result = runOpenPhishAgentUpdate($pdo);

        if ($result['status'] === 'success') {
            setFlash('OpenPhish agent completed. Imported entries: ' . (int) $result['entries_imported'], 'success');
        } else {
            setFlash('OpenPhish agent failed: ' . (string) $result['message'], 'danger');
        }

        redirect('admin/threat_intel.php');
    }
}

$feedTotal = (int) $pdo->query('SELECT COUNT(*) FROM threat_feed')->fetchColumn();
$logTotal = (int) $pdo->query('SELECT COUNT(*) FROM agent_logs')->fetchColumn();
$latestImported = (int) $pdo->query("SELECT COALESCE(entries_imported, 0) FROM agent_logs ORDER BY id DESC LIMIT 1")->fetchColumn();

$logsStmt = $pdo->query(
    'SELECT id, agent_name, entries_imported, status, run_time
     FROM agent_logs
     ORDER BY run_time DESC
     LIMIT 10'
);
$logs = $logsStmt->fetchAll();

$domainsStmt = $pdo->query(
    'SELECT domain, COUNT(*) AS hits, MAX(created_at) AS last_seen
     FROM threat_feed
     GROUP BY domain
     ORDER BY hits DESC, last_seen DESC
     LIMIT 20'
);
$topThreatDomains = $domainsStmt->fetchAll();

// Scheduler panel data (30-minute interval).
$lastRunRaw = $pdo->query(
    "SELECT run_time
     FROM agent_logs
     WHERE agent_name = 'OpenPhishAgentUpdate' AND status = 'success'
     ORDER BY run_time DESC
     LIMIT 1"
)->fetchColumn();

$lastRunText = $lastRunRaw ? (string) $lastRunRaw : 'No successful run yet';
$nextRunText = 'Pending first successful run';
$remainingText = '-';
$scheduleNote = 'Every 30 minutes (local scheduler).';

if ($lastRunRaw) {
    $lastTs = strtotime((string) $lastRunRaw);
    $nowTs = time();
    $interval = 30 * 60;
    $nextTs = $lastTs + $interval;

    if ($nextTs < $nowTs) {
        $steps = (int) floor(($nowTs - $nextTs) / $interval) + 1;
        $nextTs += $steps * $interval;
    }

    $secondsLeft = max(0, $nextTs - $nowTs);
    $minutes = (int) floor($secondsLeft / 60);
    $seconds = $secondsLeft % 60;

    $nextRunText = date('Y-m-d H:i:s', $nextTs);
    $remainingText = sprintf('%02dm %02ds', $minutes, $seconds);
}

$pageTitle = 'Threat Intelligence';
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0">Threat Intelligence</h2>
    <div class="d-flex gap-2">
        <form method="post" action="<?= e(appPath('admin/threat_intel.php')); ?>" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
            <input type="hidden" name="action" value="run_agent">
            <button type="submit" class="btn btn-outline-info btn-sm">Run OpenPhish Agent</button>
        </form>
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/dashboard.php')); ?>">Back to Dashboard</a>
        <a class="btn btn-cyan btn-sm" href="<?= e(appPath('admin/blacklist.php')); ?>">Manage Blacklist</a>
    </div>
</div>

<div class="row g-3 mb-1">
    <div class="col-md-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h6 class="mb-1">Threat Feed Entries</h6>
                <p class="display-6 mb-0"><?= $feedTotal; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h6 class="mb-1">Agent Log Runs</h6>
                <p class="display-6 mb-0"><?= $logTotal; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card ss-card h-100 border border-info">
            <div class="card-body">
                <h6 class="mb-1">Latest Import Count</h6>
                <p class="display-6 text-info mb-0"><?= $latestImported; ?></p>
            </div>
        </div>
    </div>
</div>

<div class="card ss-card mt-3">
    <div class="card-body">
        <h3 class="h6 mb-3">Agent Schedule Monitor</h3>
        <div class="row g-3">
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted">Last Run</div>
                    <div class="fw-semibold"><?= e($lastRunText); ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted">Next Run</div>
                    <div class="fw-semibold"><?= e($nextRunText); ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted">Time Remaining</div>
                    <div class="fw-semibold text-info"><?= e($remainingText); ?></div>
                </div>
            </div>
        </div>
        <p class="small text-muted mb-0 mt-3"><?= e($scheduleNote); ?></p>
    </div>
</div>

<div class="row g-3 mt-1">
    <div class="col-lg-5">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h3 class="h6 mb-3">Recent Agent Runs</h3>
                <?php if (!$logs): ?>
                    <p class="text-muted mb-0">No agent runs found yet.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th>ID</th>
                                <th>Agent</th>
                                <th>Imported</th>
                                <th>Status</th>
                                <th>Run Time</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td><?= (int) $log['id']; ?></td>
                                    <td><?= e((string) $log['agent_name']); ?></td>
                                    <td><?= (int) $log['entries_imported']; ?></td>
                                    <td>
                                        <span class="badge text-bg-<?= e(((string) $log['status']) === 'success' ? 'success' : 'danger'); ?>">
                                            <?= e((string) $log['status']); ?>
                                        </span>
                                    </td>
                                    <td><?= e((string) $log['run_time']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-7">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h3 class="h6 mb-3">Top Threat Feed Domains</h3>
                <?php if (!$topThreatDomains): ?>
                    <p class="text-muted mb-0">Threat feed is empty. Run the agent first.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Occurrences</th>
                                <th>Last Seen</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($topThreatDomains as $item): ?>
                                <tr>
                                    <td><code><?= e((string) $item['domain']); ?></code></td>
                                    <td><span class="badge text-bg-danger"><?= (int) $item['hits']; ?></span></td>
                                    <td><?= e((string) $item['last_seen']); ?></td>
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
