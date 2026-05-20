<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';

$pdo = getPDO();

// Initialize honeypot table
initHoneypotTable($pdo);

// Handle form submission
$message = null;
$messageType = 'info';
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    
    if ($action === 'send_message') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $messageText = trim((string) ($_POST['message'] ?? ''));

        if ($username === '' || $messageText === '') {
            $message = 'Please fill in all fields.';
            $messageType = 'warning';
        } elseif (strlen($username) < 2 || strlen($username) > 50) {
            $message = 'Username must be between 2 and 50 characters.';
            $messageType = 'warning';
        } elseif (strlen($messageText) < 5) {
            $message = 'Message must be at least 5 characters.';
            $messageType = 'warning';
        } else {
            try {
                $logId = logHoneypotMessage($pdo, $username, $messageText);
                $message = 'Message sent successfully! Thank you for reaching out.';
                $messageType = 'success';
                $submitted = true;
            } catch (Exception $e) {
                $message = 'An error occurred. Please try again.';
                $messageType = 'danger';
            }
        }
    }
}

$pageTitle = 'Send a Message';
require_once __DIR__ . '/includes/header.php';
?>

<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <!-- Header Section -->
            <div class="text-center mb-4">
                <h1 class="display-6 fw-bold mb-2">Send us a Message</h1>
                <p class="text-muted">Have a question or tip? Contact us directly.</p>
            </div>

            <!-- Alert Messages -->
            <?php if ($message): ?>
                <div class="alert alert-<?= e($messageType); ?> alert-dismissible fade show" role="alert">
                    <?= e($message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <!-- Message Form -->
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <form method="POST" id="honeypotForm">
                        <!-- Username Field -->
                        <div class="mb-3">
                            <label for="username" class="form-label fw-semibold">Your Username or Email</label>
                            <input 
                                type="text" 
                                class="form-control form-control-lg" 
                                id="username" 
                                name="username" 
                                placeholder="e.g., john_doe or john@example.com"
                                maxlength="50"
                                <?= $submitted ? 'disabled' : ''; ?>
                                required
                            >
                            <small class="text-muted d-block mt-1">We'll use this to contact you back.</small>
                        </div>

                        <!-- Message Field -->
                        <div class="mb-4">
                            <label for="message" class="form-label fw-semibold">Your Message</label>
                            <textarea 
                                class="form-control form-control-lg" 
                                id="message" 
                                name="message" 
                                placeholder="Type your message here..."
                                rows="5"
                                maxlength="5000"
                                <?= $submitted ? 'disabled' : ''; ?>
                                required
                            ></textarea>
                            <small class="text-muted d-block mt-1">
                                <span id="charCount">0</span> / 5000 characters
                            </small>
                        </div>

                        <!-- Hidden Action Field -->
                        <input type="hidden" name="action" value="send_message">

                        <!-- Submit Button -->
                        <button 
                            type="submit" 
                            class="btn btn-primary btn-lg w-100 fw-semibold"
                            <?= $submitted ? 'disabled' : ''; ?>
                        >
                            <span class="me-2">📨</span> Send Message
                        </button>

                        <?php if ($submitted): ?>
                            <div class="mt-3 text-center">
                                <small class="text-muted">
                                    <a href="<?= e(appPath('honeypot.php')); ?>" class="text-decoration-none">Send another message</a>
                                </small>
                            </div>
                        <?php endif; ?>
                    </form>
                </div>
            </div>

            <!-- Footer Info -->
            <div class="mt-4 text-center text-muted small">
                <p>
                    <span class="badge bg-light text-dark">✓ Secure</span>
                    <span class="badge bg-light text-dark">✓ Encrypted</span>
                    <span class="badge bg-light text-dark">✓ Anonymous</span>
                </p>
            </div>
        </div>
    </div>
</div>

<!-- JavaScript for character counter -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    const messageField = document.getElementById('message');
    const charCount = document.getElementById('charCount');
    
    if (messageField) {
        messageField.addEventListener('input', function() {
            charCount.textContent = this.value.length;
        });
        
        // Initialize on page load
        charCount.textContent = messageField.value.length;
    }
});
</script>

<style>
    .form-control-lg {
        font-size: 0.95rem;
        border-color: #e0e0e0;
        border-radius: 0.375rem;
    }
    
    .form-control-lg:focus {
        border-color: #0d6efd;
        box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.1);
    }
    
    .form-label {
        color: #1a1a1a;
        margin-bottom: 0.5rem;
    }
    
    textarea.form-control-lg {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        resize: vertical;
        min-height: 120px;
    }
    
    .btn-primary {
        background-color: #0d6efd;
        border-color: #0d6efd;
        transition: all 0.2s ease;
    }
    
    .btn-primary:hover:not(:disabled) {
        background-color: #0b5ed7;
        border-color: #0b5ed7;
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(13, 110, 253, 0.2);
    }
    
    .btn-primary:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }
    
    .card {
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        overflow: hidden;
    }
    
    .badge {
        font-size: 0.75rem;
        padding: 0.35rem 0.65rem;
        margin: 0 0.25rem;
    }
</style>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
