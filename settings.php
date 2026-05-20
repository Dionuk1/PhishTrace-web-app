<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

if (isset($_GET['lang'])) {
    $lang = trim((string) $_GET['lang']);
    setCurrentLanguage($lang);
    setFlash(t('language_saved'), 'success');
    redirect('settings.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
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
                    <a href="<?= e(appPath('settings.php?lang=en')); ?>" class="btn <?= $selectedLang === 'en' ? 'btn-cyan' : 'btn-outline-light'; ?> ss-lang-btn">
                        <img class="ss-lang-flag" src="<?= e(languageFlagUrl('en')); ?>" alt="US flag" loading="lazy">
                        <?= e(t('english')); ?>
                    </a>
                    <a href="<?= e(appPath('settings.php?lang=sq')); ?>" class="btn <?= $selectedLang === 'sq' ? 'btn-cyan' : 'btn-outline-light'; ?> ss-lang-btn">
                        <img class="ss-lang-flag" src="<?= e(languageFlagUrl('sq')); ?>" alt="Kosovo flag" loading="lazy">
                        <?= e(t('albanian')); ?>
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
