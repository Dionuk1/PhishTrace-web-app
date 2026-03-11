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

    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        setFlash(t('invalid_login_input'), 'warning');
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

                    <div class="mb-4">
                        <label class="form-label" for="email"><?= e(t('email')); ?></label>
                        <input class="form-control" type="email" id="email" name="email" required>
                        <div class="invalid-feedback"><?= e(t('invalid_login_input')); ?></div>
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
