<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
requireLogin();
requireAdmin();

$pdo = getPDO();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('admin/threat_intel.php');
    }

    $action = trim((string) ($_POST['action'] ?? ''));
    if ($action === 'run_agent') {
        require_once __DIR__ . '/../agents/agent_update.php';
        $result = runOpenPhishAgentUpdate($pdo);

        if ($result['status'] === 'success') {
            setFlash(tr('OpenPhish agent completed. Imported entries: ', 'OpenPhish agent përfundoi. Hyrje të importuara: ') . (int) $result['entries_imported'], 'success');
        } else {
            setFlash(tr('OpenPhish agent failed: ', 'OpenPhish agent dështoi: ') . (string) $result['message'], 'danger');
        }

        redirect('admin/threat_intel.php');
    }
}

$feedTotal = (int) $pdo->query('SELECT COUNT(*) FROM threat_feed')->fetchColumn();
$logTotal = (int) $pdo->query('SELECT COUNT(*) FROM agent_logs')->fetchColumn();
$latestImported = (int) $pdo->query("SELECT COALESCE(entries_imported, 0) FROM agent_logs ORDER BY id DESC LIMIT 1")->fetchColumn();
$latestUpdate = $pdo->query(
    "SELECT run_time
     FROM agent_logs
     WHERE agent_name IN ('OpenPhishAgentUpdate', 'OpenPhishAgent')
     ORDER BY run_time DESC
     LIMIT 1"
)->fetchColumn();
$latestUpdateText = $latestUpdate ? (string) $latestUpdate : tr('No updates yet', 'Nuk ka përditësime ende');

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

// Scheduler panel data (20-minute interval).
$mysqlSystemTz = $pdo->query('SELECT @@system_time_zone')->fetchColumn();
if (is_string($mysqlSystemTz) && $mysqlSystemTz !== '') {
    // Keep PHP time math aligned with MySQL/local scheduler timezone.
    if (!@date_default_timezone_set($mysqlSystemTz)) {
        date_default_timezone_set('Europe/Budapest');
    }
} else {
    date_default_timezone_set('Europe/Budapest');
}

$lastRunRaw = $pdo->query(
    "SELECT run_time
     FROM agent_logs
     WHERE agent_name = 'OpenPhishAgentUpdate' AND status = 'success'
     ORDER BY run_time DESC
     LIMIT 1"
)->fetchColumn();

$lastRunText = $lastRunRaw ? (string) $lastRunRaw : tr('No successful run yet', 'Nuk ka ekzekutim të suksesshëm ende');
$nextRunText = tr('Pending first successful run', 'Në pritje të ekzekutimit të parë me sukses');
$remainingText = '-';
$scheduleNote = tr('Every 20 minutes (local scheduler).', 'Çdo 20 minuta (scheduler lokal).');
$nextTs = null;

if ($lastRunRaw) {
    $lastTs = strtotime((string) $lastRunRaw);
    $nowTs = time();
    $interval = 20 * 60;
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

$pageTitle = t('threat_intelligence');
require_once __DIR__ . '/../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 mb-0"><?= e(t('threat_intelligence')); ?></h2>
    <div class="d-flex gap-2">
        <form method="post" action="<?= e(appPath('admin/threat_intel.php')); ?>" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
            <input type="hidden" name="action" value="run_agent">
            <button type="submit" class="btn btn-outline-info btn-sm"><?= e(t('run_openphish')); ?></button>
        </form>
        <a class="btn btn-outline-light btn-sm" href="<?= e(appPath('admin/dashboard.php')); ?>"><?= e(t('back_dashboard')); ?></a>
        <a class="btn btn-danger btn-sm" href="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt" target="_blank" rel="noopener noreferrer">Show OpenPhish Script</a>
        <a class="btn btn-cyan btn-sm" href="<?= e(appPath('admin/blacklist.php')); ?>"><?= e(t('manage_blacklist')); ?></a>
    </div>
</div>

<div class="row g-3 mb-1">
    <div class="col-md-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h6 class="mb-1"><?= e(t('threat_feed_entries')); ?></h6>
                <p class="display-6 mb-0"><?= $feedTotal; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card ss-card h-100">
            <div class="card-body">
                <h6 class="mb-1"><?= e(t('agent_log_runs')); ?></h6>
                <p class="display-6 mb-0"><?= $logTotal; ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card ss-card h-100 border border-info">
            <div class="card-body">
                <h6 class="mb-1"><?= e(t('latest_import_count')); ?></h6>
                <p class="display-6 text-info mb-0"><?= $latestImported; ?></p>
            </div>
        </div>
    </div>
</div>

<div class="card ss-card mt-3">
    <div class="card-body">
        <h3 class="h6 mb-3"><?= e(t('threat_feed_status')); ?></h3>
        <div class="row g-3">
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('source')); ?></div>
                    <div class="fw-semibold text-light">OpenPhish</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('last_update')); ?></div>
                    <div class="fw-semibold text-light"><?= e($latestUpdateText); ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('total_phishing_urls')); ?></div>
                    <div class="fw-semibold text-light"><?= $feedTotal; ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card ss-card mt-3">
    <div class="card-body">
        <h3 class="h6 mb-3"><?= e(t('agent_schedule_monitor')); ?></h3>
        <div class="row g-3">
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('last_run')); ?></div>
                    <div class="fw-semibold text-light"><?= e($lastRunText); ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('next_run')); ?></div>
                    <div class="fw-semibold text-light"><?= e($nextRunText); ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="p-3 border rounded">
                    <div class="small text-muted"><?= e(t('time_remaining')); ?></div>
                    <div
                        id="ssLiveCountdown"
                        class="fw-semibold text-info"
                        data-next-ts="<?= $nextTs !== null ? (int) $nextTs : 0; ?>"
                    ><?= e($remainingText); ?></div>
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
                <h3 class="h6 mb-3"><?= e(t('recent_agent_runs')); ?></h3>
                <?php if (!$logs): ?>
                    <p class="text-muted mb-0"><?= e(tr('No agent runs found yet.', 'Nuk ka ekzekutime të agentit ende.')); ?></p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th><?= e(tr('ID', 'ID')); ?></th>
                                <th><?= e(tr('Agent', 'Agjenti')); ?></th>
                                <th><?= e(tr('Imported', 'Importuar')); ?></th>
                                <th><?= e(tr('Status', 'Statusi')); ?></th>
                                <th><?= e(tr('Run Time', 'Koha e Ekzekutimit')); ?></th>
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
                                            <?= e(displayStatusLabel((string) $log['status'])); ?>
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
                <h3 class="h6 mb-3"><?= e(t('top_threat_domains')); ?></h3>
                <?php if (!$topThreatDomains): ?>
                    <p class="text-muted mb-0"><?= e(tr('Threat feed is empty. Run the agent first.', 'Threat feed është bosh. Ekzekuto agjentin fillimisht.')); ?></p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle mb-0">
                            <thead>
                            <tr>
                                <th><?= e(tr('Domain', 'Domeni')); ?></th>
                                <th><?= e(tr('Occurrences', 'Shfaqje')); ?></th>
                                <th><?= e(tr('Last Seen', 'Parë së Fundi')); ?></th>
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

<script>
    (function () {
        var countdownEl = document.getElementById('ssLiveCountdown');
        if (!countdownEl) return;

        var nextTs = parseInt(countdownEl.getAttribute('data-next-ts') || '0', 10);
        if (!nextTs || Number.isNaN(nextTs)) return;

        function formatRemaining(secondsLeft) {
            if (secondsLeft < 0) secondsLeft = 0;
            var minutes = Math.floor(secondsLeft / 60);
            var seconds = secondsLeft % 60;
            return String(minutes).padStart(2, '0') + 'm ' + String(seconds).padStart(2, '0') + 's';
        }

        function tick() {
            var now = Math.floor(Date.now() / 1000);
            var remaining = nextTs - now;
            countdownEl.textContent = formatRemaining(remaining);
        }

        tick();
        window.setInterval(tick, 1000);
    })();
</script>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>

