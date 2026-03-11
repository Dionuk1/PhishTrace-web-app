<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    redirect('index.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('reset_password.php');
    }

    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    if (strlen($password) < 6) {
        setFlash('Password must be at least 6 characters.', 'warning');
        redirect('reset_password.php');
    }

    if ($password !== $confirmPassword) {
        setFlash('Passwords do not match.', 'warning');
        redirect('reset_password.php');
    }

    setFlash(t('reset_password_notice'), 'info');
    redirect('login.php');
}

$pageTitle = t('reset_password');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-5 col-xl-4">
        <div class="card ss-card">
            <div class="card-body p-4">
                <h2 class="h4 mb-2"><?= e(t('reset_password')); ?></h2>
                <p class="text-muted mb-4"><?= e(t('reset_password_help')); ?></p>

                <form method="post" action="<?= e(appPath('reset_password.php')); ?>" class="needs-validation" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">

                    <div class="mb-3">
                        <label class="form-label" for="password">Password</label>
                        <div class="ss-password-shell">
                            <input class="form-control ss-password-shell__input" type="password" id="password" name="password" placeholder="Type your old password" required>
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
                        <div class="form-text">If you do not know your old password, type your new password here.</div>
                    </div>

                    <div class="mb-4">
                        <label class="form-label" for="confirm_password">Confirm password</label>
                        <div class="ss-password-shell">
                            <input class="form-control ss-password-shell__input" type="password" id="confirm_password" name="confirm_password" placeholder="Repeat your password" required>
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
                        <div class="form-text">Repeat the same password to confirm it.</div>
                    </div>

                    <button class="btn btn-cyan w-100" type="submit"><?= e(t('send_reset_link')); ?></button>
                </form>

                <p class="text-center mt-4 mb-0">
                    <a href="<?= e(appPath('login.php')); ?>" class="text-info text-decoration-none"><?= e(t('back_to_login')); ?></a>
                </p>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
