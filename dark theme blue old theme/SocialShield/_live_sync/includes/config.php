<?php
declare(strict_types=1);

/**
 * PhishTrace / SocialShield Config
 * Updated: April 2026 for Codex Agent Compatibility
 */

// Konfigurimi i sesionit para session_start()
ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Lax');

// 1. Security Headers & CSP (Zgjidhja për problemin e bllokimit)
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// CSP e përditësuar për të lejuar OpenAI dhe Bootstrap CDN
header("Content-Security-Policy: default-src 'self'; connect-src 'self' https://api.openai.com https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:;");

// 2. Session Management
if (session_status() === PHP_SESSION_NONE) {
    $sessionPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'sessions';
    if (!is_dir($sessionPath)) {
        mkdir($sessionPath, 0777, true);
    }
    session_save_path($sessionPath);
    session_start();
}

// 3. Database Configuration
if (!defined('DB_HOST')) {
    define('DB_HOST', getenv('PHISHTRACE_DB_HOST') ?: (getenv('SOCIALSHIELD_DB_HOST') ?: '127.0.0.1'));
}

if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('PHISHTRACE_DB_NAME') ?: (getenv('SOCIALSHIELD_DB_NAME') ?: 'phishtrace'));
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