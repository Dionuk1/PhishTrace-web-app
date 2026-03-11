<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
$pdo = getPDO();

$stmt = $pdo->query('SELECT title, description, category FROM security_tips ORDER BY category, id');
$tips = $stmt->fetchAll();

$pageTitle = 'Security Tips';
require_once __DIR__ . '/includes/header.php';
?>

<h2 class="h4 mb-3">Security and Privacy Tips for Social Networks</h2>
<p class="text-muted">These tips help reduce phishing, account takeover, and privacy leaks.</p>

<?php if (!$tips): ?>
    <div class="alert alert-info">No tips found. Import the SocialShield seed data first.</div>
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

