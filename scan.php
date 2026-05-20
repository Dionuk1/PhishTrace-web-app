<?php
/**
 * SCAN.PHP - URL INPUT GATEWAY
 * ----------------------------
 * This file serves as the primary interface for initiating a security scan.
 * It provides a modern, high-fidelity UI where users can input any URL for analysis.
 */

// Use strict typing to ensure code reliability and prevent type-related bugs
declare(strict_types=1);

// [PHP] Load the main functions file which contains database connections, 
// security handlers, and the core translation engine.
require_once __DIR__ . '/includes/functions.php';

// [SECURITY] Check if the user is currently authenticated. 
// If not, they will be redirected to the login page immediately.
requireLogin();

// [TRANSLATION] Define the page title using the translation helper function t().
// This ensures the title adapts to the user's selected language (English or Albanian).
$pageTitle = t('scan_url');

// [UI] Include the shared header file which contains the <head> metadata, 
// CSS links (Bootstrap, custom style.css), and the navigation bar.
require_once __DIR__ . '/includes/header.php';
?>

<!-- MAIN SCANNING STAGE -->
<div class="row justify-content-center ss-scan-stage">
    <div class="col-xl-9 col-lg-10">
        <!-- 
           SECTION: HERO SCAN PANEL
           This is the central visual component of the page. It uses a custom 
           design system (glassmorphism) and neon glow effects for a premium feel.
        -->
        <section class="ss-panel ss-panel-hero ss-scan-card">
            <!-- Decorative element for the subtle neon background glow behind the form -->
            <div class="ss-scan-card__glow" aria-hidden="true"></div>
            
            <!-- Branding and Introduction -->
            <div class="ss-scan-intro">
                <!-- Main Heading: Displayed using semantic H1 for SEO and accessibility -->
                <h1 class="ss-title mb-3"><?= e(t('scan_title')); ?></h1>
                <!-- Subheading: Briefly explains what the PhishTrace engine does -->
                <p class="ss-lead mb-4"><?= e(t('scan_subtitle')); ?></p>
            </div>

            <!-- 
               FORM: URL SUBMISSION 
               Target: result.php (Handles the logic after submission)
               Method: POST (Secures data transmission)
            -->
            <form action="<?= e(appPath('result.php')); ?>" method="post" novalidate>
                <!-- [SECURITY] CSRF Token hidden field. Prevents Cross-Site Request Forgery 
                     by validating that the form was submitted from our own domain. -->
                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                
                <!-- URL Input Container -->
                <div class="mb-4">
                    <!-- Form Label: Linked to the input ID for accessibility -->
                    <label for="url" class="form-label ss-scan-label"><?= e(t('scan_input_label')); ?></label>
                    
                    <!-- 
                       INPUT: URL ENTRY 
                       Type "url" triggers mobile browser optimizations for link entry.
                       'ss-input' class provides the custom dark/cyan theme styling.
                    -->
                    <input type="url" 
                           class="form-control form-control-lg ss-input ss-scan-input" 
                           id="url" 
                           name="url" 
                           placeholder="<?= e(t('scan_placeholder')); ?>" 
                           required 
                           autofocus>
                </div>

                <!-- ACTION BUTTONS: Submission and Navigation -->
                <div class="d-flex flex-wrap gap-3 align-items-center ss-scan-actions">
                    <!-- Submit Button: Activates the scanning workflow -->
                    <button type="submit" class="btn ss-scan-submit btn-lg px-4 fw-bold">
                        <?= e(t('scan_button')); ?>
                    </button>
                    <!-- History Link: Quick access to previous scan results -->
                    <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light btn-lg">
                        <?= e(t('history')); ?>
                    </a>
                </div>
            </form>
        </section>
    </div>
</div>

<!-- 
   COMPONENT: LOADING OVERLAY (Phase 1 UI)
   ---------------------------------------
   This overlay is hidden by default. It is activated via JavaScript 
   immediately upon form submission to provide real-time feedback.
-->
<div id="loadingOverlay" class="ss-loading-overlay">
    <!-- Animated CSS Spinner with neon glow effect -->
    <div class="ss-loading-spinner"></div>
    <!-- Technical message informing the user about the API process -->
    <div class="ss-loading-text">Analyzing link with CheckPhish AI...</div>
</div>

<!-- JAVASCRIPT: UI INTERACTIVITY -->
<script>
    /**
     * DOMContentLoaded Event:
     * Ensures all elements are loaded before binding event listeners.
     */
    document.addEventListener('DOMContentLoaded', function() {
        // Select the scanning form and the loading overlay element
        const form = document.querySelector('form');
        const overlay = document.getElementById('loadingOverlay');
        
        // Ensure elements exist to prevent runtime JavaScript errors
        if (form && overlay) {
            /**
             * Form Submit Listener:
             * Triggers as soon as the user clicks 'Start Scan'.
             */
            form.addEventListener('submit', function() {
                // Add the 'active' class to the overlay. 
                // This changes CSS opacity to 1 and visibility to visible.
                overlay.classList.add('ss-loading-overlay--active');
            });
        }
    });
</script>

<?php 
// [UI] Include the shared footer file. 
// Contains </body> and </html> tags plus global JavaScript imports.
require_once __DIR__ . '/includes/footer.php'; 
?>
