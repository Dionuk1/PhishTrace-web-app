<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

// POST only - CSRF protected language change
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token.', 'danger');
        redirect('settings.php');
    }

    $lang = trim((string) ($_POST['lang'] ?? 'en'));
    setCurrentLanguage($lang);
    setFlash(t('language_saved'), 'success');
    redirect('settings.php');
}

$selectedLang = currentLanguage();

$pageTitle = t('settings');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="card ss-card">
            <div class="card-body">
                <h2 class="h4 mb-3"><?= e(t('language_settings')); ?></h2>
                <p class="mb-3"><?= e(t('choose_language')); ?></p>
                <div class="d-flex flex-wrap gap-2">
                    <form method="post" action="<?= e(appPath('settings.php')); ?>" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="lang" value="en">
                        <button type="submit" class="btn <?= $selectedLang === 'en' ? 'btn-cyan' : 'btn-outline-light'; ?> ss-lang-btn">
                            <img class="ss-lang-flag" src="<?= e(languageFlagUrl('en')); ?>" alt="US flag" loading="lazy">
                            <?= e(t('english')); ?>
                        </button>
                    </form>
                    <form method="post" action="<?= e(appPath('settings.php')); ?>" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <input type="hidden" name="lang" value="sq">
                        <button type="submit" class="btn <?= $selectedLang === 'sq' ? 'btn-cyan' : 'btn-outline-light'; ?> ss-lang-btn">
                            <img class="ss-lang-flag" src="<?= e(languageFlagUrl('sq')); ?>" alt="Kosovo flag" loading="lazy">
                            <?= e(t('albanian')); ?>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
