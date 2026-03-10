<?php
declare(strict_types=1);

ini_set('default_charset', 'UTF-8');
if (function_exists('mb_internal_encoding')) {
    mb_internal_encoding('UTF-8');
}

// Keep sessions inside the project so local stacks do not depend on a global temp dir.
if (session_status() === PHP_SESSION_NONE) {
    $sessionPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'sessions';
    if (!is_dir($sessionPath) && !mkdir($sessionPath, 0777, true) && !is_dir($sessionPath)) {
        throw new RuntimeException('Unable to create session storage directory.');
    }
    session_save_path($sessionPath);
    session_start();
}

// Local database defaults for XAMPP/Laragon.
// Override with environment variables when needed.

if (!defined('DB_HOST')) {
    define('DB_HOST', getenv('SOCIALSHIELD_DB_HOST') ?: '127.0.0.1');
}

if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('SOCIALSHIELD_DB_NAME') ?: 'socialshield');
}

if (!defined('DB_USER')) {
    define('DB_USER', getenv('SOCIALSHIELD_DB_USER') ?: 'root');
}

if (!defined('DB_PASS')) {
    $dbPass = getenv('SOCIALSHIELD_DB_PASS');
    define('DB_PASS', $dbPass !== false ? $dbPass : '');
}

if (!defined('DB_CHARSET')) {
    define('DB_CHARSET', 'utf8mb4');
}
