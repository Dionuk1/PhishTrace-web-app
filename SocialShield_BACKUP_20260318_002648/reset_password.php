<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    redirect('index.php');
}

// GET: Validate reset token from email link
$token = (string) ($_GET['token'] ?? '');
$tokenValid = false;
$userEmail = null;

if ($token !== '' && strlen($token) === 64) {
    $pdo = getPDO();
    
    // Ensure reset token columns exist
    ensureTableColumn($pdo, 'users', 'reset_token', 'VARCHAR(64) NULL');
    ensureTableColumn($pdo, 'users', 'reset_token_expires', 'TIMESTAMP NULL');
    
    // Validate token and check expiry (1 hour validity)
    $stmt = $pdo->prepare(
        'SELECT email FROM users 
         WHERE reset_token = :token 
         AND reset_token_expires > NOW() 
         LIMIT 1'
    );
    $stmt->execute(['token' => $token]);
    $user = $stmt->fetch();
    
    if ($user) {
        $tokenValid = true;
        $userEmail = $user['email'];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('reset_password.php');
    }

    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');
    $postToken = (string) ($_POST['token'] ?? '');

    if (strlen($password) < 6) {
        setFlash('Password must be at least 6 characters.', 'warning');
        redirect('reset_password.php' . ($postToken ? '?token=' . urlencode($postToken) : ''));
    }

    if ($password !== $confirmPassword) {
        setFlash('Passwords do not match.', 'warning');
        redirect('reset_password.php' . ($postToken ? '?token=' . urlencode($postToken) : ''));
    }

    // Validate token again on POST
    if ($postToken === '' || strlen($postToken) !== 64) {
        setFlash('Invalid or missing reset token.', 'danger');
        redirect('login.php');
    }

    $pdo = getPDO();
    $stmt = $pdo->prepare(
        'SELECT id, email FROM users 
         WHERE reset_token = :token 
         AND reset_token_expires > NOW() 
         LIMIT 1'
    );
    $stmt->execute(['token' => $postToken]);
    $user = $stmt->fetch();

    if (!$user) {
        setFlash('Invalid or expired reset token.', 'danger');
        redirect('login.php');
    }

    // Update password and clear reset token
    $updateStmt = $pdo->prepare(
        'UPDATE users 
         SET password_hash = :password_hash,
             reset_token = NULL,
             reset_token_expires = NULL
         WHERE id = :id'
    );
    $updateStmt->execute([
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'id' => $user['id']
    ]);

    setFlash('Password successfully reset. You can now log in with your new password.', 'success');
    redirect('login.php');
}

$pageTitle = t('reset_password');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-5 col-xl-4">
        <div class="card ss-card">
            <div class="card-body p-4">
                <?php if (!$tokenValid): ?>
                    <div class="alert alert-danger">
                        <strong>Invalid or Expired Reset Link</strong>
                        <p class="mb-0">This password reset link is invalid or has expired. Please request a new password reset link.</p>
                    </div>
                    <p class="text-center mb-0">
                        <a href="<?= e(appPath('login.php')); ?>" class="btn btn-cyan">Back to Login</a>
                    </p>
                <?php else: ?>
                    <h2 class="h4 mb-2"><?= e(t('reset_password')); ?></h2>
                    <p class="text-muted mb-4">Enter your new password for: <strong><?= e($userEmail); ?></strong></p>

                    <form method="post" action="<?= e(appPath('reset_password.php')); ?>" class="needs-validation" novalidate>
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="token" value="<?= e($token); ?>">

                        <div class="mb-3">
                            <label class="form-label" for="password">New Password</label>
                            <div class="ss-password-shell">
                                <input class="form-control ss-password-shell__input" type="password" id="password" name="password" placeholder="Enter your new password" required>
                                <button
                                    type="button"
                                    class="btn ss-password-peek"
                                    data-monkey-toggle
                                    data-target="password"
                                    aria-label="Show password"
                                    aria-pressed="false">
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                                </button>
                            </div>
                            <div class="form-text">Password must be at least 6 characters.</div>
                        </div>

                        <div class="mb-4">
                            <label class="form-label" for="confirm_password">Confirm New Password</label>
                            <div class="ss-password-shell">
                                <input class="form-control ss-password-shell__input" type="password" id="confirm_password" name="confirm_password" placeholder="Repeat your new password" required>
                                <button
                                    type="button"
                                    class="btn ss-password-peek"
                                    data-monkey-toggle
                                    data-target="confirm_password"
                                    aria-label="Show password"
                                    aria-pressed="false">
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                                </button>
                            </div>
                            <div class="form-text">Repeat the same password to confirm.</div>
                        </div>

                        <button class="btn btn-cyan w-100" type="submit">Reset Password</button>
                    </form>

                    <p class="text-center mt-4 mb-0">
                        <a href="<?= e(appPath('login.php')); ?>" class="text-info text-decoration-none"><?= e(t('back_to_login')); ?></a>
                    </p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
