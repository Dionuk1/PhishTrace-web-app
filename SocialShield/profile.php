<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

$pdo = getPDO();
$user = currentUser();
$stmt = $pdo->prepare('SELECT name, email, role, created_at FROM users WHERE id = :id LIMIT 1');
$stmt->execute(['id' => (int) ($user['id'] ?? 0)]);
$profile = $stmt->fetch() ?: ['name' => '', 'email' => '', 'role' => '', 'created_at' => ''];

$pageTitle = t('profile');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card ss-card">
            <div class="card-body">
                <h2 class="h4 mb-3"><?= e(t('profile')); ?></h2>
                <p><strong><?= e(t('name_label')); ?>:</strong> <?= e((string) $profile['name']); ?></p>
                <p><strong><?= e(t('email_address')); ?>:</strong> <?= e((string) $profile['email']); ?></p>
                <p><strong><?= e(t('role_label')); ?>:</strong> <?= e((string) $profile['role']); ?></p>
                <p class="mb-0"><strong><?= e(t('joined_label')); ?>:</strong> <?= e((string) $profile['created_at']); ?></p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
