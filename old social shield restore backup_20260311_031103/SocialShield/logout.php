<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

if (isLoggedIn()) {
    logoutUser();
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
setFlash('You have been logged out.', 'info');
redirect('login.php');
