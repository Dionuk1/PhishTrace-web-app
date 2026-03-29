<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    redirect('index.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('register.php');
    }

    if (!checkRateLimit('reg_' . ($_SERVER['REMOTE_ADDR'] ?? 'guest'), 3, 3600)) {
        setFlash(t('too_many_reg'), 'danger');
        redirect('register.php');
    }

    $name = trim((string) ($_POST['name'] ?? ''));
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        setFlash(t('invalid_details'), 'warning');
        redirect('register.php');
    }

    if (strlen($password) < 6) {
        setFlash(t('password_min_length'), 'warning');
        redirect('register.php');
    }

    if ($password !== $confirmPassword) {
        setFlash(t('password_confirm_help'), 'warning');
        redirect('register.php');
    }

    $pdo = getPDO();
    $existsStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $existsStmt->execute(['email' => $email]);
    if ($existsStmt->fetch()) {
        setFlash(t('email_exists'), 'warning');
        redirect('login.php');
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :password_hash, :role)');
    $stmt->execute([
        'name' => $name,
        'email' => $email,
        'password_hash' => $passwordHash,
        'role' => 'user',
    ]);

    $newUserId = (int) $pdo->lastInsertId();
    loginUser([
        'id' => $newUserId,
        'name' => $name,
        'email' => $email,
        'role' => 'user',
    ]);
    setFlash(t('welcome_msg'), 'success');
    redirect('scan.php');
}

$pageTitle = t('register');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-6">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <h2 class="h4 mb-3"><?= e(t('create_account')); ?></h2>
                <form method="post" action="<?= e(appPath('register.php')); ?>" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <div class="mb-3">
                        <label for="name" class="form-label"><?= e(t('full_name')); ?></label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label"><?= e(t('email_address')); ?></label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label"><?= e(t('password')); ?></label>
                        <div class="ss-password-shell">
                            <input type="password" class="form-control ss-password-shell__input" id="password" name="password" placeholder="<?= e(t('url_placeholder')); ?>" required>
                            <button
                                type="button"
                                class="btn ss-password-peek"
                                data-monkey-toggle
                                data-target="password"
                                aria-label="<?= e(t('show_password')); ?>"
                                aria-pressed="false">
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                            </button>
                        </div>
                        <div class="form-text"><?= e(t('password_min_length')); ?></div>
                    </div>
                    <div class="mb-3">
                        <label for="confirm_password" class="form-label"><?= e(t('confirm_password')); ?></label>
                        <div class="ss-password-shell">
                            <input type="password" class="form-control ss-password-shell__input" id="confirm_password" name="confirm_password" placeholder="<?= e(t('url_placeholder')); ?>" required>
                            <button
                                type="button"
                                class="btn ss-password-peek"
                                data-monkey-toggle
                                data-target="confirm_password"
                                aria-label="<?= e(t('show_password')); ?>"
                                aria-pressed="false">
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                            </button>
                        </div>
                        <div class="form-text"><?= e(t('password_confirm_help')); ?></div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100"><?= e(t('register')); ?></button>
                </form>
                <p class="text-center mt-3 mb-0">
                    <span class="text-muted"><?= e(t('already_have_account')); ?></span>
                    <a href="<?= e(appPath('login.php')); ?>" class="text-info text-decoration-none"><?= e(t('login_here')); ?></a>
                </p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>


