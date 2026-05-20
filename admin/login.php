<?php
/**
 * ADMIN LOGIN PAGE
 * ----------------
 * Provides a dedicated secure entry point for administrators only.
 * Validates user credentials and ensures the 'admin' role is present before granting access.
 */

declare(strict_types=1);

// Include core functions for database, authentication, and session handling
require_once __DIR__ . '/../includes/functions.php';

/**
 * REDIRECT IF ALREADY LOGGED IN AS ADMIN
 * If the user is already authenticated as an admin, send them directly to the admin dashboard.
 */
if (isAdmin()) {
    redirect('admin/index.php');
}

/**
 * HANDLE LOGIN SUBMISSION
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Standard CSRF protection to prevent unauthorized login attempts
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(tr('Invalid CSRF token.', 'Token CSRF i pavlefshëm.'), 'danger');
        redirect('admin/login.php');
    }

    // Sanitize and validate email/password inputs
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = (string) ($_POST['password'] ?? '');

    // Basic validation check for empty fields
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        setFlash(tr('Please provide valid login details.', 'Ju lutem jepni të dhëna të vlefshme hyrjeje.'), 'warning');
        redirect('admin/login.php');
    }

    // Initialize database connection
    $pdo = getPDO();
    
    // Attempt to fetch the user record by email
    $stmt = $pdo->prepare('SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    /**
     * CREDENTIAL VALIDATION & ADMIN ROLE CHECK
     * 1. Check if user exists.
     * 2. Verify password against the secure hash in DB.
     * 3. CRITICAL: Ensure the user's role is 'admin'.
     */
    if (!$user || !password_verify($password, (string) $user['password_hash']) || ($user['role'] ?? '') !== 'admin') {
        setFlash(tr('Unauthorized access. Only admins can login here.', 'Akses i paautorizuar. Vetëm administratorët mund të hyjnë këtu.'), 'danger');
        redirect('admin/login.php');
    }

    // Successful authentication: log user into session and redirect to admin panel
    loginUser($user);
    setFlash(tr('Admin login successful.', 'Hyrja si administrator ishte e suksesshme.'), 'success');
    redirect('admin/index.php');
}

// Page title for the browser tab
$pageTitle = 'Admin Secure Login';
// Include the shared header layout
require_once __DIR__ . '/../includes/header.php';
?>

<!-- ADMIN LOGIN INTERFACE -->
<div class="row justify-content-center ss-page-fade-in">
    <div class="col-lg-5">
        <div class="card ss-console-card shadow-lg border-danger">
            <div class="card-body p-4 p-lg-5">
                <!-- Visual warning icon for admin area -->
                <div class="text-center mb-4">
                    <div class="ss-section-icon ss-section-icon--warning mx-auto" style="width: 60px; height: 60px; font-size: 1.5rem;">🔒</div>
                    <h2 class="h4 mt-3 mb-1">Admin Control Center</h2>
                    <p class="text-secondary small">Secure authentication required for administrator access.</p>
                </div>

                <!-- Dedicated Admin Login Form -->
                <form method="post" action="<?= e(appPath('admin/login.php')); ?>" novalidate>
                    <!-- CSRF Token for security -->
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">

                    <!-- Email Input Field -->
                    <div class="mb-3">
                        <label for="email" class="form-label text-light">Admin Email</label>
                        <input type="email" class="form-control ss-input-dark" id="email" name="email" placeholder="admin@socialshield.local" required>
                    </div>

                    <!-- Password Input Field with Visibility Toggle -->
                    <div class="mb-4">
                        <label for="password" class="form-label text-light">Secret Key / Password</label>
                        <div class="ss-password-shell">
                            <input type="password" class="form-control ss-input-dark ss-password-shell__input" id="password" name="password" required>
                            <!-- Password peek button with monkey animation -->
                            <button
                                type="button"
                                class="btn ss-password-peek"
                                data-monkey-toggle
                                data-target="password"
                                aria-label="Show password"
                                aria-pressed="false">
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--hidden" aria-hidden="true">&#x1F648;</span>
                                <span class="ss-password-peek__emoji ss-password-peek__emoji--visible" aria-hidden="true">&#x1F435;</span>
                            </button>
                        </div>
                    </div>

                    <!-- Submit Button with distinct admin styling -->
                    <button type="submit" class="btn btn-cyan w-100 py-3 fw-bold">AUTHENTICATE ADMIN</button>
                </form>

                <!-- Helpful links for returning to public area -->
                <div class="mt-4 text-center">
                    <a href="<?= e(appPath('index.php')); ?>" class="text-secondary text-decoration-none small">&larr; Return to SocialShield Homepage</a>
                </div>
            </div>
        </div>
    </div>
</div>

<?php 
// Include the shared footer layout
require_once __DIR__ . '/../includes/footer.php'; 
?>
