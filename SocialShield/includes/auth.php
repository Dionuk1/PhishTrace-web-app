<?php
// Session and authentication helpers.

declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * Return true when user is logged in.
 */
function isLoggedIn(): bool
{
    return isset($_SESSION['user']) && is_array($_SESSION['user']);
}

/**
 * Return true when current user is admin.
 */
function isAdmin(): bool
{
    return isLoggedIn() && ($_SESSION['user']['role'] ?? '') === 'admin';
}

/**
 * Return currently logged in user array or null.
 */
function currentUser(): ?array
{
    return isLoggedIn() ? $_SESSION['user'] : null;
}

/**
 * Stop page access if not logged in.
 */
function requireLogin(): void
{
    if (!isLoggedIn()) {
        setFlash('Please login to continue.', 'warning');
        redirect('login.php');
    }
}

/**
 * Stop page access if not admin.
 */
function requireAdmin(): void
{
    if (!isAdmin()) {
        setFlash('Admin access is required.', 'danger');
        redirect('index.php');
    }
    
    // A-5: Check admin session timeout
    checkAdminSessionTimeout();
}

/**
 * Store minimal user fields in session.
 */
function loginUser(array $user): void
{
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'name' => $user['name'],
        'email' => $user['email'],
        'role' => $user['role'],
    ];
    session_regenerate_id(true);
}

/**
 * Logout user safely.
 */
function logoutUser(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    session_destroy();
}

/**
 * Check admin session timeout (15 minutes of inactivity).
 */
function checkAdminSessionTimeout(): void
{
    if (!isAdmin()) {
        return;
    }
    
    $timeout = 900; // 15 minutes in seconds
    $key = 'admin_last_activity';
    $now = time();
    
    if (isset($_SESSION[$key])) {
        $elapsed = $now - (int) $_SESSION[$key];
        if ($elapsed > $timeout) {
            logoutUser();
            setFlash('Admin session expired due to inactivity. Please login again.', 'warning');
            redirect('login.php');
        }
    }
    
    $_SESSION[$key] = $now;
}
