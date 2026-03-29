<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    redirect('index.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token.', 'danger');
        redirect('login.php');
    }

    if (!checkRateLimit('login_' . ($_SERVER['REMOTE_ADDR'] ?? 'guest'), 5, 300)) {
        setFlash('Too many login attempts. Please try again later.', 'danger');
        redirect('login.php');
    }

    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = (string) ($_POST['password'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        setFlash('Please provide valid login details.', 'warning');
        redirect('login.php');
    }

    $pdo = getPDO();
    $stmt = $pdo->prepare('SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, (string) $user['password_hash'])) {
        setFlash('Email or password is incorrect.', 'danger');
        redirect('login.php');
    }

    loginUser($user);
    setFlash('Login successful.', 'success');
    if (($user['role'] ?? '') === 'admin') {
        redirect('admin/dashboard.php');
    }
    redirect('index.php');
}

$pageTitle = 'Login';
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-5">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <h2 class="h4 mb-3">Login</h2>
                <form method="post" action="<?= e(appPath('login.php')); ?>" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <div class="mb-3">
                        <label for="email" class="form-label">Email address</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="ss-password-shell">
                            <input type="password" class="form-control ss-password-shell__input" id="password" name="password" required>
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
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <p class="text-center mt-3 mb-2">
                    <a href="<?= e(appPath('reset_password.php')); ?>" class="text-info text-decoration-none">Forgot your password? Reset it here.</a>
                </p>
                <p class="text-center mb-0">
                    <span class="text-muted">Don't have an account?</span>
                    <a href="<?= e(appPath('register.php')); ?>" class="text-info text-decoration-none">Register here</a>
                </p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
