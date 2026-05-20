<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../controllers/HoneypotController.php';
requireLogin();
requireAdmin();

$controller = new HoneypotController(getPDO());
$notice = null;
$noticeType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string) ($_POST['csrf_token'] ?? '');

    if (!verifyCsrfToken($token)) {
        $notice = 'Invalid request token.';
        $noticeType = 'danger';
    } else {
        $result = $controller->handlePost($_POST);
        $notice = $result['message'];
        $noticeType = $result['ok'] ? 'success' : 'warning';
    }
}

$selectedProfileId = isset($_GET['profile_id']) ? (int) $_GET['profile_id'] : null;
$data = $controller->pageData($selectedProfileId);
$pageTitle = 'Honeypot Fake Profile System';

require_once __DIR__ . '/../views/index.view.php';
