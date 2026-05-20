<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../api/fake_profiles/FakeProfileController.php';
require_once __DIR__ . '/../api/fake_profiles/AttackerBehaviorService.php';
requireLogin();
requireAdmin();

$pageTitle = 'Honeypot Fake Profiles';
$pdo = getPDO();
$repository = new FakeProfileRepository($pdo);
$repository->ensureTables();
$controller = new FakeProfileController($repository);
$notice = null;
$noticeType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string) ($_POST['csrf_token'] ?? '');

    if (!verifyCsrfToken($token)) {
        $notice = 'Invalid request token.';
        $noticeType = 'danger';
    } else {
        $action = (string) ($_POST['action'] ?? '');

        if ($action === 'create_profile') {
            $result = $controller->createProfile(
                (string) ($_POST['username'] ?? ''),
                (string) ($_POST['bio'] ?? ''),
                (string) ($_POST['profile_type'] ?? 'normal'),
                isset($_POST['auto_username'])
            );
        } elseif ($action === 'receive_message') {
            $result = $controller->receiveMessage(
                (int) ($_POST['profile_id'] ?? 0),
                (string) ($_POST['sender_username'] ?? ''),
                (string) ($_POST['message_text'] ?? '')
            );
        } else {
            $result = ['ok' => false, 'message' => 'Unknown action.'];
        }

        $notice = $result['message'];
        $noticeType = $result['ok'] ? 'success' : 'warning';
    }
}

$profiles = $repository->profiles();
$stats = $repository->stats();
$recentMessages = $repository->recentMessages(12);
$attackerService = new AttackerBehaviorService();
$topAttackers = $attackerService->topAttackers($repository->allMessages(), 8);

require_once __DIR__ . '/../includes/header.php';
?>

<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="h4 fw-bold mb-1">Honeypot Fake Profile System</h1>
            <p class="text-muted mb-0">Create fake social profiles, receive messages, and analyze attacker behavior.</p>
        </div>
        <a class="btn btn-outline-secondary" href="<?= e(appPath('admin/honeypot_dashboard.php')); ?>">Message Honeypot</a>
    </div>

    <?php if ($notice): ?>
        <div class="alert alert-<?= e($noticeType); ?>"><?= e($notice); ?></div>
    <?php endif; ?>

    <div class="row g-3 mb-4">
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">Total Profiles</div><div class="display-6"><?= (int) $stats['total_profiles']; ?></div></div></div>
        </div>
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">Total Messages</div><div class="display-6"><?= (int) $stats['total_messages']; ?></div></div></div>
        </div>
        <div class="col-md-4">
            <div class="card ss-card"><div class="card-body"><div class="text-muted">High Risk Messages</div><div class="display-6 text-danger"><?= (int) $stats['high_risk_messages']; ?></div></div></div>
        </div>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-lg-5">
            <div class="card ss-card h-100">
                <div class="card-header fw-semibold">Create Fake Profile</div>
                <div class="card-body">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="action" value="create_profile">

                        <div class="mb-3">
                            <label class="form-label">Profile Type</label>
                            <select class="form-select" name="profile_type">
                                <option value="gamer">gamer</option>
                                <option value="crypto">crypto</option>
                                <option value="influencer">influencer</option>
                                <option value="normal">normal</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input class="form-control" name="username" placeholder="Leave blank if auto-generate is checked">
                        </div>

                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" id="autoUsername" name="auto_username" value="1" checked>
                            <label class="form-check-label" for="autoUsername">Auto-generate random username</label>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Bio</label>
                            <textarea class="form-control" name="bio" rows="3" placeholder="Optional profile bio"></textarea>
                        </div>

                        <button class="btn btn-primary" type="submit">Create Profile</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-lg-7">
            <div class="card ss-card h-100">
                <div class="card-header fw-semibold">Send Test Message To Profile</div>
                <div class="card-body">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="action" value="receive_message">

                        <div class="row g-3">
                            <div class="col-md-6">
                                <label class="form-label">Fake Profile</label>
                                <select class="form-select" name="profile_id" required>
                                    <option value="">Choose profile</option>
                                    <?php foreach ($profiles as $profile): ?>
                                        <option value="<?= (int) $profile['id']; ?>">
                                            <?= e((string) $profile['username']); ?> (<?= e((string) $profile['profile_type']); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Sender Username</label>
                                <input class="form-control" name="sender_username" placeholder="attacker_01" required>
                            </div>
                        </div>

                        <div class="mt-3 mb-3">
                            <label class="form-label">Message Text</label>
                            <textarea class="form-control" name="message_text" rows="5" placeholder="Paste suspicious social media DM here..." required></textarea>
                        </div>

                        <button class="btn btn-primary" type="submit">Receive And Analyze</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-lg-5">
            <div class="card ss-card h-100">
                <div class="card-header fw-semibold">Fake Profiles</div>
                <div class="list-group list-group-flush">
                    <?php if (!$profiles): ?>
                        <div class="list-group-item text-muted">No fake profiles yet.</div>
                    <?php endif; ?>

                    <?php foreach ($profiles as $profile): ?>
                        <div class="list-group-item">
                            <div class="d-flex justify-content-between">
                                <strong><?= e((string) $profile['username']); ?></strong>
                                <span class="badge bg-secondary"><?= e((string) $profile['profile_type']); ?></span>
                            </div>
                            <small class="text-muted"><?= e((string) $profile['bio']); ?></small>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <div class="col-lg-7">
            <div class="card ss-card h-100">
                <div class="card-header fw-semibold">Top Attackers</div>
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Sender</th>
                                <th>Messages</th>
                                <th>URLs</th>
                                <th>Repeated Keywords</th>
                                <th>Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!$topAttackers): ?>
                                <tr><td colspan="5" class="text-center text-muted py-3">No attackers tracked yet.</td></tr>
                            <?php endif; ?>

                            <?php foreach ($topAttackers as $attacker): ?>
                                <?php
                                $level = (string) $attacker['suspicious_level'];
                                $badge = $level === 'HIGH' ? 'bg-danger' : ($level === 'MEDIUM' ? 'bg-warning text-dark' : 'bg-success');
                                ?>
                                <tr>
                                    <td><strong><?= e((string) $attacker['sender_username']); ?></strong></td>
                                    <td><?= (int) $attacker['message_count']; ?></td>
                                    <td><?= (int) $attacker['url_count']; ?></td>
                                    <td><?= e(implode(', ', $attacker['repeated_keywords'] ?? [])); ?></td>
                                    <td><span class="badge <?= e($badge); ?>"><?= e($level); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="card ss-card">
        <div class="card-header fw-semibold">Recent Activity</div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-light">
                    <tr>
                        <th>Profile</th>
                        <th>Sender</th>
                        <th>Message</th>
                        <th>Keywords</th>
                        <th>URLs</th>
                        <th>Risk</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (!$recentMessages): ?>
                        <tr><td colspan="7" class="text-center text-muted py-4">No messages received yet.</td></tr>
                    <?php endif; ?>

                    <?php foreach ($recentMessages as $message): ?>
                        <?php
                        $keywords = json_decode((string) $message['keywords_json'], true) ?: [];
                        $urls = json_decode((string) $message['urls_json'], true) ?: [];
                        $riskLevel = (string) $message['risk_level'];
                        $rowClass = $riskLevel === 'HIGH' ? 'table-danger' : '';
                        $badge = $riskLevel === 'HIGH' ? 'bg-danger' : ($riskLevel === 'MEDIUM' ? 'bg-warning text-dark' : 'bg-success');
                        ?>
                        <tr class="<?= e($rowClass); ?>">
                            <td>
                                <strong><?= e((string) $message['profile_username']); ?></strong>
                                <div><small class="text-muted"><?= e((string) $message['profile_type']); ?></small></div>
                            </td>
                            <td><?= e((string) $message['sender_username']); ?></td>
                            <td style="max-width: 340px;"><?= e((string) $message['message_text']); ?></td>
                            <td><?= e(implode(', ', $keywords)); ?></td>
                            <td><?= count($urls); ?></td>
                            <td><span class="badge <?= e($badge); ?>"><?= e($riskLevel); ?> (<?= (int) $message['risk_score']; ?>)</span></td>
                            <td><small><?= e((string) $message['created_at']); ?></small></td>
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
