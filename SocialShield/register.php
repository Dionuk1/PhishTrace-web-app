<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    redirect('index.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token.', 'danger');
        redirect('register.php');
    }

    $name = trim((string) ($_POST['name'] ?? ''));
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        setFlash('Please provide valid name and email.', 'warning');
        redirect('register.php');
    }

    if (strlen($password) < 6) {
        setFlash('Password must be at least 6 characters.', 'warning');
        redirect('register.php');
    }

    if ($password !== $confirmPassword) {
        setFlash('Passwords do not match.', 'warning');
        redirect('register.php');
    }

    $pdo = getPDO();
    $existsStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $existsStmt->execute(['email' => $email]);
    if ($existsStmt->fetch()) {
        setFlash('Email already exists. Please login.', 'warning');
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
    setFlash('Registration successful. Welcome to SocialShield.', 'success');
    redirect('scan.php');
}

$pageTitle = 'Register';
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-6">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <h2 class="h4 mb-3">Create account</h2>
                <form method="post" action="<?= e(appPath('register.php')); ?>" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <div class="mb-3">
                        <label for="name" class="form-label">Full name</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
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
                    <div class="mb-3">
                        <label for="confirm_password" class="form-label">Confirm password</label>
                        <div class="ss-password-shell">
                            <input type="password" class="form-control ss-password-shell__input" id="confirm_password" name="confirm_password" required>
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
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Register</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
