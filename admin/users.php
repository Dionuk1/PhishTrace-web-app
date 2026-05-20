<?php
/**
 * ADMIN USER MANAGEMENT PANEL
 * --------------------------
 * Allows administrators to monitor registered accounts, update user details,
 * reset security points, and permanently delete accounts.
 */

declare(strict_types=1);

// Core system dependencies and security protocols
require_once __DIR__ . '/../includes/functions.php';

/**
 * ACCESS CONTROL
 * Strictly restricts this page to administrators only. 
 * Non-admin attempts result in an immediate redirect to the main index.
 */
requireLogin();
requireAdmin();

// Initialize PDO database connection for administrative actions
$pdo = getPDO();
$currentAdmin = currentUser();
$editUser = null;

/**
 * POST REQUEST HANDLER (ADMIN ACTIONS)
 * Processes all destructive or state-changing actions submitted via forms.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CRITICAL: Validate CSRF token for every administrative state change
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash(tr('Security mismatch. Action denied.', 'Mospërputhje sigurie. Veprimi u refuzua.'), 'danger');
        redirect('admin/users.php');
    }

    // Determine which action the admin is attempting
    $action = (string) ($_POST['action'] ?? '');
    $targetUserId = (int) ($_POST['user_id'] ?? 0);

    /**
     * ACTION: UPDATE USER NAME
     * Allows renaming accounts (e.g., to fix typos or inappropriate names).
     */
    if ($action === 'update_name') {
        $newName = trim((string) ($_POST['name'] ?? ''));
        if ($targetUserId > 0 && $newName !== '') {
            $stmt = $pdo->prepare('UPDATE users SET name = :name WHERE id = :id');
            $stmt->execute(['name' => $newName, 'id' => $targetUserId]);
            setFlash(tr('User name updated successfully.', 'Emri i përdoruesit u përditësua me sukses.'), 'success');
        }
        redirect('admin/users.php');
    }

    /**
     * ACTION: RESET SECURITY POINTS (User Request A)
     * Resets the user's earned 'security_score' to zero.
     * Useful for testing or penalizing incorrect system usage.
     */
    if ($action === 'reset_points') {
        if ($targetUserId > 0) {
            // Update the security_score field to 0 for the targeted user
            $stmt = $pdo->prepare('UPDATE users SET security_score = 0 WHERE id = :id');
            $stmt->execute(['id' => $targetUserId]);
            setFlash(tr('User points have been reset to 0.', 'Pikët e përdoruesit u rikthyen në 0.'), 'info');
        }
        redirect('admin/users.php');
    }

    /**
     * ACTION: DELETE USER ACCOUNT
     * Permanently removes a user record from the 'users' table.
     * SECURITY: Prevents an admin from accidentally deleting their own active session.
     */
    if ($action === 'delete') {
        if ($targetUserId > 0 && $targetUserId !== (int) ($currentAdmin['id'] ?? 0)) {
            // Execute the permanent deletion query
            $stmt = $pdo->prepare('DELETE FROM users WHERE id = :id');
            $stmt->execute(['id' => $targetUserId]);
            setFlash(tr('User account permanently deleted.', 'Llogaria e përdoruesit u fshi përgjithmonë.'), 'success');
        } else {
            setFlash(tr('You cannot delete your own account.', 'Nuk mund të fshini llogarinë tuaj aktuale.'), 'warning');
        }
        redirect('admin/users.php');
    }
}

/**
 * GET REQUEST HANDLER (EDIT MODE)
 * ------------------------------
 * Retrieves user data from the database when the 'edit' parameter is present in the URL.
 * This allows the admin to see current data in the form before making changes.
 */
if (isset($_GET['edit'])) {
    // SECURITY: Cast the ID to an integer to prevent SQL injection and ensure it's a valid number.
    $editId = (int) $_GET['edit'];

    // Only proceed if the ID is a positive integer.
    if ($editId > 0) {
        /**
         * ERROR PREVENTION:
         * We use a specific variable name ($editStmt) to avoid conflicts with other queries on the page.
         * The 'LIMIT 1' ensures we only fetch one specific record.
         */
        $editStmt = $pdo->prepare('SELECT id, name, email, role FROM users WHERE id = :id LIMIT 1');
        $editStmt->execute(['id' => $editId]);
        
        // Fetch the user data. If no user is found, $editUser remains null, and the form won't show.
        $editUser = $editStmt->fetch() ?: null;
    }
}

/**
 * DATA RETRIEVAL
 * Fetch the complete list of registered users, sorted by registration date.
 */
$stmt = $pdo->query(
    "SELECT id, name, email, role, security_score, created_at 
     FROM users 
     ORDER BY created_at DESC"
);
$users = $stmt->fetchAll();

// Set page title and include standard header
$pageTitle = 'User Management | Admin';
require_once __DIR__ . '/../includes/header.php';
?>

<!-- USER MANAGEMENT INTERFACE -->
<div class="ss-page-fade-in">
    <!-- Panel Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="ss-title mb-1">User Management</h1>
            <p class="text-secondary small">Monitor activity, adjust scores, and manage access levels.</p>
        </div>
        <a href="<?= e(appPath('admin/index.php')); ?>" class="btn btn-outline-light btn-sm">&larr; Dashboard</a>
    </div>

    <!-- EDIT SECTION: Shown only when a user is selected for renaming -->
    <?php if ($editUser): ?>
        <div class="card ss-console-card mb-4 border-info">
            <div class="card-body p-4">
                <h3 class="h5 mb-3 text-info">Update Profile Information</h3>
                <form method="post" action="<?= e(appPath('admin/users.php')); ?>" class="row g-3 align-items-end">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                    <input type="hidden" name="action" value="update_name">
                    <input type="hidden" name="user_id" value="<?= (int) $editUser['id']; ?>">
                    <div class="col-md-5">
                        <label class="form-label text-secondary small">Email (Identifier)</label>
                        <input type="text" class="form-control ss-input-dark" value="<?= e((string) $editUser['email']); ?>" disabled>
                    </div>
                    <div class="col-md-5">
                        <label for="name" class="form-label">Full Name</label>
                        <input type="text" id="name" name="name" class="form-control ss-input-dark" value="<?= e((string) $editUser['name']); ?>" required>
                    </div>
                    <div class="col-md-2 d-grid gap-2">
                        <button type="submit" class="btn btn-cyan">Save</button>
                    </div>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <!-- REGISTERED USERS TABLE -->
    <div class="card ss-console-card shadow-lg">
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-hover align-middle mb-0 ss-table-modern">
                    <thead class="bg-black">
                        <tr>
                            <th class="ps-4">ID</th>
                            <th>Name / Email</th>
                            <th>Role</th>
                            <th>Score</th>
                            <th>Registered</th>
                            <th class="pe-4 text-end">Control Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td class="ps-4 text-secondary small"><?= (int) $user['id']; ?></td>
                                <td>
                                    <div class="fw-bold"><?= e((string) $user['name']); ?></div>
                                    <div class="text-secondary small"><?= e((string) $user['email']); ?></div>
                                </td>
                                <td>
                                    <span class="badge rounded-pill bg-<?= ($user['role'] === 'admin') ? 'info' : 'secondary'; ?> bg-opacity-25 text-<?= ($user['role'] === 'admin') ? 'info' : 'secondary'; ?> border border-<?= ($user['role'] === 'admin') ? 'info' : 'secondary'; ?> border-opacity-50">
                                        <?= strtoupper((string) $user['role']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="fw-bold text-cyan"><?= (int) ($user['security_score'] ?? 0); ?></span> <small class="text-secondary">pts</small>
                                </td>
                                <td class="text-secondary small">
                                    <?= e(date('M j, Y', strtotime((string) $user['created_at']))); ?>
                                </td>
                                <td class="pe-4 text-end">
                                    <!-- Prevent admin from performing actions on themselves to avoid locking the session -->
                                    <?php if ((int) $user['id'] === (int) ($currentAdmin['id'] ?? 0)): ?>
                                        <span class="badge text-bg-light p-2">Current Session</span>
                                    <?php else: ?>
                                        <div class="d-flex justify-content-end gap-2">
                                            <!-- Edit Name Trigger -->
                                            <a href="?edit=<?= (int) $user['id']; ?>" class="btn btn-sm btn-outline-info" title="Edit Name">✎</a>
                                            
                                            <!-- Reset Points Button (Icon: rotate-left) -->
                                            <form method="post" action="<?= e(appPath('admin/users.php')); ?>" onsubmit="return confirmAdminAction('Are you sure you want to RESET ALL POINTS for this user?', 'Reset to 0');">
                                                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                                <input type="hidden" name="action" value="reset_points">
                                                <input type="hidden" name="user_id" value="<?= (int) $user['id']; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-warning" title="Reset Points">↺</button>
                                            </form>

                                            <!-- Delete User Button -->
                                            <form method="post" action="<?= e(appPath('admin/users.php')); ?>" onsubmit="return confirmAdminAction('CRITICAL: This will PERMANENTLY delete the user and all their scan history. Proceed?', 'Delete User');">
                                                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="user_id" value="<?= (int) $user['id']; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" title="Delete User">🗑</button>
                                            </form>
                                        </div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- ADMINISTRATIVE MODALS & SCRIPTS -->
<script>
/**
 * CONFIRM ADMIN ACTION
 * --------------------
 * Native JS Confirmation Modal to prevent accidental deletions or point resets.
 * Matches the user request for "JavaScript Confirmation Modals".
 */
function confirmAdminAction(message, actionLabel) {
    return confirm(`${message}\n\nTarget Action: ${actionLabel}`);
}
</script>

<?php 
// Include shared footer layout
require_once __DIR__ . '/../includes/footer.php'; 
?>
