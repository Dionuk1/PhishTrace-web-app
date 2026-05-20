<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
$pdo = getPDO();

$stmt = $pdo->query('SELECT title, description, category FROM security_tips ORDER BY category, id');
$tips = $stmt->fetchAll();

$pageTitle = t('security_tips');
require_once __DIR__ . '/includes/header.php';
?>

<h2 class="h4 mb-3"><?= e(t('tips_title')); ?></h2>
<p class="text-muted"><?= e(t('tips_intro')); ?></p>

<?php if (!$tips): ?>
    <div class="alert alert-info"><?= e(t('tips_empty')); ?></div>
<?php else: ?>
    <div class="row g-4">
        <?php foreach ($tips as $tip): ?>
            <div class="col-md-6">
                <div class="card h-100 shadow-sm">
                    <div class="card-body">
                        <span class="badge text-bg-primary mb-2"><?= e((string) $tip['category']); ?></span>
                        <h3 class="h6"><?= e((string) $tip['title']); ?></h3>
                        <p class="mb-0"><?= e((string) $tip['description']); ?></p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

