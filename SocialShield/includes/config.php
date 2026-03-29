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
    
    // A-1: Harden session cookie flags
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');
    
    // Only enable secure flag if HTTPS is available
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        ini_set('session.cookie_secure', '1');
    }
    
    session_start();
}

// A-4: Add security headers to prevent common attacks
if (!headers_sent()) {
    // Prevent clickjacking
    header('X-Frame-Options: SAMEORIGIN');
    
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Enable XSS filter (legacy browsers)
    header('X-XSS-Protection: 1; mode=block');
    
    // Referrer policy (don't leak full URL)
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy (allows current inline styles/scripts used in app)
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'");
}

// A-6: Configure application error logging
$appLogDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'logs';
if (!is_dir($appLogDir) && !mkdir($appLogDir, 0700, true) && !is_dir($appLogDir)) {
    throw new RuntimeException('Unable to create log directory.');
}

$appLogFile = $appLogDir . DIRECTORY_SEPARATOR . 'app_error.log';
ini_set('error_log', $appLogFile);

// Ensure log file has secure permissions
if (!file_exists($appLogFile)) {
    touch($appLogFile);
    chmod($appLogFile, 0600);
}

// Local database defaults for XAMPP/Laragon.
// Override with environment variables when needed.

if (!defined('DB_HOST')) {
    define('DB_HOST', getenv('PHISHTRACE_DB_HOST') ?: (getenv('SOCIALSHIELD_DB_HOST') ?: '127.0.0.1'));
}

if (!defined('DB_NAME')) {
    // Default to legacy local DB so existing users are not "lost" after branding changes.
    define('DB_NAME', getenv('PHISHTRACE_DB_NAME') ?: (getenv('SOCIALSHIELD_DB_NAME') ?: 'socialshield'));
}

if (!defined('DB_USER')) {
    define('DB_USER', getenv('PHISHTRACE_DB_USER') ?: (getenv('SOCIALSHIELD_DB_USER') ?: 'root'));
}

if (!defined('DB_PASS')) {
    $dbPass = getenv('PHISHTRACE_DB_PASS');
    if ($dbPass === false) {
        $dbPass = getenv('SOCIALSHIELD_DB_PASS');
    }
    define('DB_PASS', $dbPass !== false ? $dbPass : '');
}

if (!defined('DB_CHARSET')) {
    define('DB_CHARSET', 'utf8mb4');
}

