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

    // ✅ UPDATE PASSWORD AND CLEAR TOKEN
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

$pageTitle = 'Reset Password';
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-5">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <h2 class="h4 mb-3">Reset Password</h2>
                
                <?php if ($tokenValid && $userEmail): ?>
                    <p class="text-muted mb-3">Reset password for: <strong><?= e($userEmail); ?></strong></p>
                    <form method="post" action="<?= e(appPath('reset_password.php')); ?>" novalidate>
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="token" value="<?= e($token); ?>">
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">New Password</label>
                            <div class="ss-password-shell">
                                <input type="password" class="form-control ss-password-shell__input" id="password" name="password" required>
                                <button type="button" class="btn ss-password-peek" data-monkey-toggle data-target="password" aria-label="Show password" aria-pressed="false">
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                                </button>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm New Password</label>
                            <div class="ss-password-shell">
                                <input type="password" class="form-control ss-password-shell__input" id="confirm_password" name="confirm_password" required>
                                <button type="button" class="btn ss-password-peek" data-monkey-toggle data-target="confirm_password" aria-label="Show password" aria-pressed="false">
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                    <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                                </button>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100">Reset Password</button>
                    </form>
                <?php else: ?>
                    <p class="text-danger">Invalid or expired reset token. <a href="<?= e(appPath('login.php')); ?>">Return to login</a></p>
                <?php endif; ?>
                
                <p class="text-center mt-3 mb-0">
                    <a href="<?= e(appPath('login.php')); ?>" class="text-info text-decoration-none">Back to Login</a>
                </p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>