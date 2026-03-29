<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

// Handle GET-based language switch from the navbar dropdown
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['lang'])) {
    $newLang = (string) ($_GET['lang']);
    setCurrentLanguage($newLang);
    
    $referer = $_SERVER['HTTP_REFERER'] ?? appPath('index.php');
    header('Location: ' . $referer);
    exit;
}

// Handle POST-based language switch from the settings form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(t('invalid_csrf'), 'danger');
        redirect('settings.php');
    }

    $newLang = (string) ($_POST['lang'] ?? 'en');
    setCurrentLanguage($newLang);
    setFlash(t('language_saved'), 'success');
    
    $referer = $_SERVER['HTTP_REFERER'] ?? appPath('index.php');
    header('Location: ' . $referer);
    exit;
}

$pageTitle = t('language_settings');
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-6">
        <div class="card ss-card">
            <div class="card-body">
                <h2 class="h4 mb-3"><?= e(t('language_settings')); ?></h2>
                <p class="text-muted small"><?= e(t('choose_language')); ?></p>
                
                <form method="post" action="<?= e(appPath('settings.php')); ?>">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <div class="mb-3">
                        <div class="form-check ss-lang-option">
                            <input class="form-check-input" type="radio" name="lang" id="lang_en" value="en" <?= currentLanguage() === 'en' ? 'checked' : ''; ?>>
                            <label class="form-check-label d-flex align-items-center" for="lang_en">
                                <img src="<?= e(languageFlagUrl('en')); ?>" class="me-2" alt="EN" width="20">
                                <?= e(t('english')); ?>
                            </label>
                        </div>
                        <div class="form-check ss-lang-option">
                            <input class="form-check-input" type="radio" name="lang" id="lang_sq" value="sq" <?= currentLanguage() === 'sq' ? 'checked' : ''; ?>>
                            <label class="form-check-label d-flex align-items-center" for="lang_sq">
                                <img src="<?= e(languageFlagUrl('sq')); ?>" class="me-2" alt="SQ" width="20">
                                <?= e(t('albanian')); ?>
                            </label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary"><?= e(t('save_settings')); ?></button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
