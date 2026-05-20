<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/header.php';

$profiles = $data['profiles'];
$stats = $data['stats'];
$selectedProfileId = (int) $data['selected_profile_id'];
$chatMessages = $data['chat_messages'];
$recentMessages = $data['recent_messages'];
$topAttackers = $data['top_attackers'];
?>

<style>
    .hp-shell { max-width: 1220px; margin: 0 auto; }
    .hp-card { border: 1px solid #e3e7ee; border-radius: 8px; background: #fff; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06); }
    .hp-profile { display: flex; gap: 12px; padding: 12px; text-decoration: none; color: inherit; border-bottom: 1px solid #edf0f5; }
    .hp-profile:hover, .hp-profile.active { background: #f6f8fb; }
    .hp-avatar { width: 48px; height: 48px; border-radius: 50%; background: linear-gradient(135deg, #e8eef8, #ccd9ee); display: grid; place-items: center; font-weight: 700; color: #334155; flex: 0 0 auto; }
    .hp-type { border-radius: 999px; padding: 2px 8px; font-size: 12px; background: #eef2ff; color: #3730a3; }
    .hp-chat { min-height: 420px; max-height: 520px; overflow-y: auto; padding: 16px; background: #f8fafc; }
    .hp-bubble { max-width: 78%; border-radius: 8px; padding: 10px 12px; margin-bottom: 10px; background: #fff; border: 1px solid #e5e7eb; }
    .hp-risk-low { background: #dcfce7; color: #166534; }
    .hp-risk-medium { background: #fef3c7; color: #92400e; }
    .hp-risk-high { background: #fee2e2; color: #991b1b; }
    .hp-row-high { background: #fff1f2; }
    .hp-stat { min-height: 108px; }
</style>

<div class="container-fluid py-4">
    <div class="hp-shell">
        <div class="d-flex justify-content-between align-items-start mb-4">
            <div>
                <h1 class="h4 fw-bold mb-1">Honeypot Fake Profile System</h1>
                <p class="text-muted mb-0">Instagram-like fake profiles that collect messages and detect phishing behavior.</p>
            </div>
        </div>

        <?php if ($notice): ?>
            <div class="alert alert-<?= e($noticeType); ?>"><?= e($notice); ?></div>
        <?php endif; ?>

        <div class="row g-3 mb-4">
            <div class="col-md-4"><div class="hp-card hp-stat p-3"><div class="text-muted">Total Profiles</div><div class="display-6"><?= (int) $stats['total_profiles']; ?></div></div></div>
            <div class="col-md-4"><div class="hp-card hp-stat p-3"><div class="text-muted">Total Messages</div><div class="display-6"><?= (int) $stats['total_messages']; ?></div></div></div>
            <div class="col-md-4"><div class="hp-card hp-stat p-3"><div class="text-muted">High Risk Alerts</div><div class="display-6 text-danger"><?= (int) $stats['high_risk_alerts']; ?></div></div></div>
        </div>

        <div class="row g-3 mb-4">
            <div class="col-lg-4">
                <div class="hp-card mb-3">
                    <div class="p-3 border-bottom fw-semibold">Fake Profiles</div>
                    <?php if (!$profiles): ?>
                        <div class="p-3 text-muted">No profiles yet. Create one below.</div>
                    <?php endif; ?>
                    <?php foreach ($profiles as $profile): ?>
                        <?php $active = (int) $profile['id'] === $selectedProfileId; ?>
                        <a class="hp-profile <?= $active ? 'active' : ''; ?>" href="?profile_id=<?= (int) $profile['id']; ?>">
                            <div class="hp-avatar"><?= e(strtoupper(substr((string) $profile['username'], 0, 1))); ?></div>
                            <div class="flex-grow-1">
                                <div class="d-flex justify-content-between gap-2">
                                    <strong>@<?= e((string) $profile['username']); ?></strong>
                                    <span class="hp-type"><?= e((string) $profile['profile_type']); ?></span>
                                </div>
                                <small class="text-muted"><?= e((string) $profile['bio']); ?></small>
                            </div>
                        </a>
                    <?php endforeach; ?>
                </div>

                <div class="hp-card p-3">
                    <h2 class="h6 fw-semibold mb-3">Create Profile</h2>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="action" value="create_profile">
                        <div class="mb-2">
                            <select class="form-select" name="profile_type">
                                <option value="gamer">gamer</option>
                                <option value="crypto">crypto</option>
                                <option value="influencer">influencer</option>
                                <option value="normal">normal</option>
                            </select>
                        </div>
                        <div class="mb-2">
                            <input class="form-control" name="username" placeholder="username">
                        </div>
                        <div class="form-check mb-2">
                            <input class="form-check-input" type="checkbox" id="autoUsername" name="auto_username" value="1" checked>
                            <label class="form-check-label" for="autoUsername">Auto-generate username</label>
                        </div>
                        <div class="mb-3">
                            <textarea class="form-control" name="bio" rows="2" placeholder="bio"></textarea>
                        </div>
                        <button class="btn btn-primary w-100" type="submit">Create Fake Profile</button>
                    </form>
                </div>
            </div>

            <div class="col-lg-8">
                <div class="hp-card">
                    <div class="p-3 border-bottom fw-semibold">Chat Interface</div>
                    <div class="hp-chat">
                        <?php if (!$chatMessages): ?>
                            <div class="text-muted">No messages for this profile yet.</div>
                        <?php endif; ?>
                        <?php foreach ($chatMessages as $message): ?>
                            <?php $riskClass = 'hp-risk-' . strtolower((string) $message['risk_level']); ?>
                            <div class="hp-bubble">
                                <div class="d-flex justify-content-between gap-2 mb-1">
                                    <strong><?= e((string) $message['sender_username']); ?></strong>
                                    <span class="badge <?= e($riskClass); ?>"><?= e((string) $message['risk_level']); ?></span>
                                </div>
                                <div><?= e((string) $message['message_text']); ?></div>
                                <small class="text-muted"><?= e((string) $message['timestamp']); ?></small>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <div class="p-3 border-top">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                            <input type="hidden" name="action" value="send_message">
                            <input type="hidden" name="profile_id" value="<?= $selectedProfileId; ?>">
                            <div class="row g-2">
                                <div class="col-md-4">
                                    <input class="form-control" name="sender_username" placeholder="sender username" required>
                                </div>
                                <div class="col-md-6">
                                    <input class="form-control" name="message_text" placeholder="message text" required>
                                </div>
                                <div class="col-md-2">
                                    <button class="btn btn-primary w-100" type="submit" <?= $selectedProfileId <= 0 ? 'disabled' : ''; ?>>Send</button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-3">
            <div class="col-lg-8">
                <div class="hp-card">
                    <div class="p-3 border-bottom fw-semibold">Recent Messages</div>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0 align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>Profile</th>
                                    <th>Sender</th>
                                    <th>Message</th>
                                    <th>Risk</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!$recentMessages): ?>
                                    <tr><td colspan="5" class="text-center text-muted py-4">No recent messages.</td></tr>
                                <?php endif; ?>
                                <?php foreach ($recentMessages as $message): ?>
                                    <?php
                                    $riskLevel = (string) $message['risk_level'];
                                    $riskClass = 'hp-risk-' . strtolower($riskLevel);
                                    $rowClass = $riskLevel === 'HIGH' ? 'hp-row-high' : '';
                                    ?>
                                    <tr class="<?= e($rowClass); ?>">
                                        <td>@<?= e((string) $message['profile_username']); ?><br><small class="text-muted"><?= e((string) $message['profile_type']); ?></small></td>
                                        <td><?= e((string) $message['sender_username']); ?></td>
                                        <td style="max-width: 320px;"><?= e((string) $message['message_text']); ?></td>
                                        <td><span class="badge <?= e($riskClass); ?>"><?= e($riskLevel); ?> (<?= (int) $message['risk_score']; ?>)</span></td>
                                        <td><small><?= e((string) $message['timestamp']); ?></small></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="hp-card">
                    <div class="p-3 border-bottom fw-semibold">Top Attackers</div>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Sender</th>
                                    <th>Msgs</th>
                                    <th>URLs</th>
                                    <th>Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!$topAttackers): ?>
                                    <tr><td colspan="4" class="text-center text-muted py-4">No attackers yet.</td></tr>
                                <?php endif; ?>
                                <?php foreach ($topAttackers as $attacker): ?>
                                    <?php $levelClass = 'hp-risk-' . strtolower((string) $attacker['suspicion_level']); ?>
                                    <tr>
                                        <td><?= e((string) $attacker['sender_username']); ?></td>
                                        <td><?= (int) $attacker['total_messages']; ?></td>
                                        <td><?= (int) $attacker['total_urls']; ?></td>
                                        <td><span class="badge <?= e($levelClass); ?>"><?= e((string) $attacker['suspicion_level']); ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>
