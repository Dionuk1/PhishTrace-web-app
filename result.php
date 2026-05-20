<?php
/**
 * RESULT.PHP - CYBERSECURITY ANALYSIS DASHBOARD (HYBRID ENGINE)
 * -------------------------------------------------------------
 * This is the primary engine for visualizing URL analysis results.
 * It combines fast server-side heuristics with deep asynchronous AI scanning.
 */

// Enforce strict typing for better memory management and error catching
declare(strict_types=1);

// [PHP] Load global functions, database utilities, and authentication checks
require_once __DIR__ . '/includes/functions.php';

// [SECURITY] Ensure only logged-in users can access the analysis dashboard
requireLogin();

/**
 * INITIAL REQUEST PROCESSING (POST)
 * --------------------------------
 * When coming from scan.php, we process the rule-based scan immediately.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // [SECURITY] Verify CSRF token to prevent cross-site malicious form submissions
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('Invalid CSRF token. Please try again.', 'danger');
        redirect('scan.php');
    }

    // [INPUT] Sanitize the submitted URL to prevent injection attacks
    $url = sanitizeUrlInput($_POST['url'] ?? '');
    if ($url === '') {
        setFlash('Please submit a valid URL.', 'warning');
        redirect('scan.php');
    }

    // Get DB connection
    $pdo = getPDO();

    // [LOGIC] Step 1: Perform fast local heuristic analysis (PhishTrace Rule Engine)
    $analysis = analyzeUrl($url, $pdo);

    // If the URL is fundamentally broken or malformed, return to scan page
    if (!$analysis['valid']) {
        setFlash($analysis['reasons'][0] ?? 'Invalid URL.', 'danger');
        redirect('scan.php');
    }

    // [LOGIC] Step 2: Save the scan to the database for history and user points
    $user = currentUser();
    $scanId = saveScan(
        (int) $user['id'],
        $analysis['url'],
        $analysis['domain'],
        (int) $analysis['risk_score'],
        $analysis['status'],
        $analysis['reasons'],
        $pdo
    );

    // [SESSION] Store scan data for historical reference and AI summarization
    $_SESSION['latest_scan_id'] = $scanId;
    $summary = [
        'url' => $analysis['url'],
        'domain' => $analysis['domain'],
        'status' => $analysis['status'],
        'risk_score' => $analysis['risk_score'],
        'reasons' => $analysis['reasons'] ?? [],
        'valid' => $analysis['valid'] ?? true,
    ];
    $_SESSION['latest_scan_summary'] = $summary;
    $_SESSION['latest_scan_analysis'] = $summary; // Ensure backend compatibility

    // Set flag to show achievement popup once the page loads
    $_SESSION['show_achievement_popup'] = true;
} else {
    /**
     * PAGE REFRESH HANDLING (GET)
     * Retrieves the last performed scan from the session if the user refreshes.
     */
    $scanId = (int) ($_SESSION['latest_scan_id'] ?? 0);
    $scanSummary = $_SESSION['latest_scan_summary'] ?? null;

    // If no scan data is found, redirect back to the entry page
    if (!is_array($scanSummary) || empty($scanSummary['url'])) {
        redirect('scan.php');
    }

    $analysis = $scanSummary;
}

// [UI] Helper variables for styling based on the risk level
$statusLabel = statusDisplayLabel((string) $analysis['status']);
$riskTone = riskBarTone((string) $analysis['status']);

// [ACHIEVEMENTS] Check if the user unlocked any milestones during this scan
$showAchievementPopup = !empty($_SESSION['show_achievement_popup']);
if ($showAchievementPopup) {
    unset($_SESSION['show_achievement_popup']); // Consume the flag
}

$latestAchievement = null;
$currentUserData = currentUser();
$userTotalPoints = (int) ($currentUserData['security_score'] ?? 0);

if ($showAchievementPopup && $currentUserData) {
    // Fetch newly unlocked achievement data if applicable
    $popupData = getUserAchievementNotificationData((int) $currentUserData['id'], getPDO());
    $latestAchievement = $popupData['latest_unlock'] ?? null;
}

// Set dynamic page title
$pageTitle = 'AI Security Assistant';
// Include layout header
require_once __DIR__ . '/includes/header.php';
?>

<!-- DASHBOARD UI STRUCTURE -->
<div class="ss-page-fade-in">
    <!-- HERO SECTION (Restored to Classic) -->
    <section class="ss-panel ss-panel-hero mb-4">
        <div class="d-flex flex-wrap justify-content-between align-items-end gap-3">
            <div>
                <p class="ss-kicker mb-2">AI Security Assistant</p>
                <h1 class="ss-title mb-3">Cybersecurity analysis dashboard</h1>
                <p class="ss-lead mb-0">Professional phishing analysis for <code><?= e($analysis['domain']); ?></code> with threat indicators and on-demand AI explanation.</p>
            </div>
            <div class="ss-chip">SCAN COMPLETE</div>
        </div>
    </section>

    <!-- CORE RESULTS -->
    <section class="card ss-console-card ss-assistant-dashboard shadow-lg">
        <div class="card-body p-4 p-lg-5">
            <div class="row g-4">
                <!-- PANEL: Scan Summary -->
                <div class="col-lg-5">
                    <div class="ss-assistant-section">
                        <div class="ss-section-header mb-4">
                            <span class="ss-section-icon">URL</span>
                            <h2 class="h4 mb-0">Analysis Metadata</h2>
                        </div>
                        <div class="ss-result-meta bg-black bg-opacity-25 rounded-3 p-3">
                            <div class="ss-result-meta-row py-2 border-bottom border-secondary border-opacity-10">
                                <span class="text-secondary small">Investigated URL</span>
                                <code id="ss-url-display" class="text-info"><?= e($analysis['url']); ?></code>
                            </div>
                            <div class="ss-result-meta-row py-2">
                                <span class="text-secondary small">Threat Status</span>
                                <span id="ss-status-pill"
                                    class="ss-status-pill ss-status-pill--<?= e($riskTone); ?>"><?= e($statusLabel); ?></span>
                            </div>
                            <!-- AI Snapshot container -->
                            <div id="ss-screenshot-container" class="mt-3"></div>
                        </div>

                        <!-- METRIC: Safety Score (Animated) -->
                        <div class="ss-risk-meter mt-4">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span class="text-light fw-bold">Hybrid Safety Score</span>
                                <span id="ss-risk-percent"
                                    class="ss-risk-percent ss-risk-percent--<?= e($riskTone); ?>"><?= (int) $analysis['risk_score']; ?>%</span>
                            </div>
                            <div class="ss-progress-track">
                                <div id="ss-risk-bar" class="ss-progress-bar ss-progress-bar--<?= e($riskTone); ?>"
                                    style="width: <?= (int) $analysis['risk_score']; ?>%"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- PANEL: Detected Indicators -->
                <div class="col-lg-7">
                    <div class="ss-assistant-section">
                        <div class="ss-section-header mb-4">
                            <span class="ss-section-icon ss-section-icon--warning">!</span>
                            <h2 class="h4 mb-0">Detected Indicators</h2>
                        </div>
                        <ul id="ss-threat-list" class="ss-threat-list">
                            <?php foreach (($analysis['threat_alerts'] ?? []) as $alert): ?>
                                <li class="ss-threat-item ss-threat-item--<?= e((string) $alert['tone']); ?>">
                                    <span class="ss-threat-icon"><?= e((string) $alert['icon']); ?></span>
                                    <span><?= e((string) $alert['text']); ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- AI SECURITY ASSISTANT (Restored to Classic PHP Flow) -->
    <section id="ss-summary-panel" class="card ss-console-card mt-4 ss-page-fade-in">
        <div class="card-body p-4 p-lg-5">
            <div class="ss-assistant-section">
                <div class="ss-section-header">
                    <span class="ss-section-icon ss-section-icon--ai">AI</span>
                    <div>
                        <h2 class="h4 mb-1">AI Security Assistant</h2>
                        <p class="text-secondary mb-0">Generate a natural-language explanation and recommendations from the detected indicators.</p>
                    </div>
                </div>

                <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
                    <form method="post" action="<?= e(appPath('ai_summary_loading.php')); ?>" class="m-0">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()); ?>">
                        <button type="submit" class="btn btn-primary ss-ai-trigger">Generate AI Summary</button>
                    </form>
                    <a href="<?= e(appPath('ai_summary_popup.php')); ?>" class="btn btn-outline-light btn-sm" target="_blank" onclick="window.open(this.href,'aiSummaryPopup','width=980,height=780'); return false;">Open CheckPhish Summary Popup</a>
                    <span class="ss-chip">Source: CheckPhish or fallback security model</span>
                </div>

                <?php 
                $aiReport = $_SESSION['latest_ai_report'] ?? null; 
                if ($aiReport): 
                ?>
                    <div class="ss-ai-summary-box mt-3">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                            <h3 class="h5 mb-0">AI Summary</h3>
                            <span class="ss-status-pill ss-status-pill--ai"><?= e(strtoupper((string) ($aiReport['source'] ?? 'AI'))); ?></span>
                        </div>
                        <div class="ss-ai-summary-content"><?= renderAiReportHtml((string) $aiReport['text']); ?></div>
                    </div>
                <?php else: ?>
                    <div class="ss-ai-placeholder mt-3">
                        <span class="ss-spinner" aria-hidden="true"></span>
                        <div>
                            <strong>AI summary ready on request</strong>
                            <p class="mb-0 text-secondary">Submit the button above to generate a PHP-rendered explanation from the current threat indicators.</p>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <!-- NAVIGATION ACTIONS -->
    <div class="d-grid gap-2 d-md-flex mt-4 justify-content-center">
        <a href="<?= e(appPath('scan.php')); ?>" class="btn btn-cyan px-4">New Analysis</a>
        <a href="<?= e(appPath('history.php')); ?>" class="btn btn-outline-light">Scan History</a>
    </div>
</div>

<script>
    /**
     * [HYBRID INTELLIGENCE & AUTO-RECOVERY ENGINE]
     */
    const CHECKPHISH_API_KEY = 'frjk6y11c3pn7srlxzn6s2j44gjiv06189zyxn0zdrcqxxa86prw3rsb01exqsk2';
    const targetUrl = '<?= e($analysis['url']); ?>';
    const userBasePoints = <?= $userTotalPoints; ?>;
    const isPostRequest = <?= $_SERVER['REQUEST_METHOD'] === 'POST' ? 'true' : 'false'; ?>;
    
    const fallbackData = {
        url: '<?= e($analysis['url']); ?>',
        disposition: '<?= e($analysis['status']); ?>',
        insights: '<?= e(str_replace(["\r", "\n"], ' ', implode(". ", $analysis['reasons'] ?? []))); ?>',
        risk_score: <?= (int) $analysis['risk_score']; ?>
    };

    function performLocalHeuristics(url) {
        let score = 0;
        let flags = [];
        const lowUrl = url.toLowerCase();
        
        const shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'adf.ly'];
        if (shorteners.some(s => lowUrl.includes(s))) {
            score += 20;
            flags.push("Shortened URL detected (High-risk obfuscation)");
        }
        
        const patterns = [/[0o][0o]gle/, /faceb[0o][0o]k/, /arnbank/, /p[4a]yp[4a]l/];
        if (patterns.some(p => p.test(lowUrl))) {
            score += 35;
            flags.push("Typosquatting/Homograph imitation of trusted brand");
        }
        
        if (lowUrl.includes('@')) { score += 20; flags.push("Deceptive @ symbol found in path"); }
        const domain = lowUrl.split('/')[2] || "";
        if ((domain.match(/\d/g) || []).length > 4) { score += 15; flags.push("Excessive numeric characters in domain"); }
        if ((domain.match(/-/g) || []).length > 3) { score += 10; flags.push("Unusual hyphenation levels"); }

        return { score, flags };
    }

    function setSkeletons(active) {
        const uiElements = [document.getElementById('ss-status-pill'), document.getElementById('ss-risk-percent')];
        uiElements.forEach(el => {
            if (active && el) el.innerHTML = '<span class="ss-skeleton ss-skeleton--pill"></span>';
        });
    }

    async function startScan() {
        setSkeletons(true);
        let hasResolved = false;

        const jsHeuristics = performLocalHeuristics(targetUrl);
        
        const fallbackTimer = setTimeout(() => {
            if (!hasResolved) {
                console.warn("AI Cluster Overloaded: Initiating Auto-Recovery.");
                hasResolved = true;
                updateDashboard(fallbackData, jsHeuristics);
            }
        }, 10000); 
        
        try {
            const subResp = await fetch('https://developers.bolster.ai/api/neo/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, urlInfo: { url: targetUrl } })
            });
            
            const subData = await subResp.json();
            
            // FIX JS CRASH: String conversion guard
            if (!subData.jobID) {
                let errormsg = subData.error || subData.message || "API Cluster Unreachable";
                const displayMsg = (errormsg && typeof errormsg === 'string') ? errormsg.toLowerCase() : 'analysis complete';
                throw new Error(displayMsg);
            }
            
            const jobID = subData.jobID;

            let status = 'pending';
            let result = null;
            let attempts = 0;
            const maxAttempts = 10; 
            
            while ((status === 'pending' || status === 'started') && attempts < maxAttempts && !hasResolved) {
                attempts++;
                await new Promise(r => setTimeout(r, 3000));
                
                const stResp = await fetch('https://developers.bolster.ai/api/neo/scan/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, jobID: jobID, insights: true })
                });
                
                result = await stResp.json();
                status = (result && result.status && typeof result.status === 'string') ? result.status.toLowerCase() : 'pending';

                if (result && result.error) break;
                if (status === 'completed' || (result && result.disposition)) break;
            }

            if (!hasResolved) {
                clearTimeout(fallbackTimer);
                if (result && result.disposition) {
                    hasResolved = true;
                    updateDashboard(result, jsHeuristics);
                } else {
                    throw new Error("API Timeout");
                }
            }
            
        } catch (e) {
            if (!hasResolved) {
                hasResolved = true;
                console.error("Hybrid Failover:", e.message);
                updateDashboard(fallbackData, jsHeuristics); 
            }
        }
    }

    function updateDashboard(data, jsHeuristics = null) {
        try {
            let rawDisp = data.disposition;
            let disposition = (typeof rawDisp === 'string') ? rawDisp : (rawDisp && rawDisp.name ? rawDisp.name : 'unknown');
            
            const isSafe = String(disposition).toLowerCase() === 'clean';
            const safetyScore = data.risk_score || (isSafe ? 98 : 12); 
            const tone = isSafe ? 'safe' : 'danger';
            const pointsToAdd = isSafe ? 15 : 1; 

            const skeletons = document.querySelectorAll('.ss-skeleton');
            skeletons.forEach(s => s.remove());

            const pill = document.getElementById('ss-status-pill');
            if (pill) {
                pill.className = `ss-status-pill ss-status-pill--${tone}`;
                pill.textContent = disposition.toUpperCase();
            }

            animateValue('ss-risk-percent', 0, safetyScore, 1500, tone);
            const bar = document.getElementById('ss-risk-bar');
            if (bar) {
                bar.className = `ss-progress-bar ss-progress-bar--${tone}`;
                bar.style.width = `${safetyScore}%`;
            }

            const threatList = document.getElementById('ss-threat-list');
            if (threatList) {
                threatList.innerHTML = '';
                const alerts = [];
                alerts.push({ tone: tone, icon: isSafe ? '✅' : '⚠️', text: `AI Cluster: ${disposition.toUpperCase()}` });
                if (jsHeuristics && jsHeuristics.flags.length > 0) {
                    jsHeuristics.flags.forEach(f => {
                        alerts.push({ tone: 'danger', icon: '🚩', text: f });
                    });
                }
                if (data.insights && (data.insights.includes('OpenPhish') || data.insights.includes('Blacklist'))) {
                    alerts.unshift({ tone: 'danger', icon: '🚨', text: "Identified by Global Threat Feed" });
                }

                alerts.forEach(a => {
                    const li = document.createElement('li');
                    li.className = `ss-threat-item ss-threat-item--${a.tone}`;
                    li.innerHTML = `<span class="ss-threat-icon">${a.icon}</span><span>${a.text}</span>`;
                    threatList.appendChild(li);
                });
            }

            // Achievement Check
            if (isPostRequest && !window.achievementShown) {
                window.achievementShown = true;
                showAchievementNotification(disposition, pointsToAdd);
            }

            if (data.screenshot_path || data.screenshot) {
                const container = document.getElementById('ss-screenshot-container');
                if (container) {
                    container.innerHTML = `<img src="${data.screenshot_path || data.screenshot}" class="img-fluid rounded border border-secondary border-opacity-10 shadow-sm mt-3" alt="Evidence Snapshot">`;
                }
            }

            if (isPostRequest && !window.achievementShown) {
                window.achievementShown = true;
                showAchievementNotification(disposition, pointsToAdd);
            }

        } catch (err) {
            console.error("Dashboard update crashed:", err);
        }
    }

    function animateValue(id, start, end, duration, tone) {
        const obj = document.getElementById(id);
        if (!obj) return;
        obj.className = `ss-risk-percent ss-risk-percent--${tone}`;
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start) + "%";
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    /**
     * [RESTORED] ACHIEVEMENT NOTIFICATION (Classic Design)
     */
    function showAchievementNotification(disposition, points) {
        const isSafe = String(disposition).toLowerCase() === 'clean';
        const title = isSafe ? 'Shield Champion' : 'Threat Hunter';
        const desc = isSafe ? 'Secure site confirmed!' : 'Phishing trap activated!';
        const icon = isSafe ? '🏆' : '🛡️';
        const toneClass = isSafe ? '' : 'ss-achievement-toast--danger';

        const toast = document.createElement('div');
        toast.className = `ss-achievement-toast ${toneClass}`;
        
        toast.innerHTML = `
            <div class="ss-achievement-toast__header">
                <div class="ss-achievement-toast__label">
                    <span class="ss-achievement-toast__label-icon">🏆</span>
                    Achievement Unlocked
                </div>
                <button type="button" class="ss-achievement-toast__close" onclick="this.closest('.ss-achievement-toast').remove()">×</button>
            </div>
            <div class="ss-achievement-toast__divider"></div>
            <div class="ss-achievement-toast__body">
                <div class="ss-achievement-toast__icon">${icon}</div>
                <div class="ss-achievement-toast__content">
                    <h4 class="ss-achievement-toast__title">${title}</h4>
                    <p class="ss-achievement-toast__desc">${desc}</p>
                    <div class="ss-achievement-toast__pts">+${points} points earned</div>
                </div>
            </div>
            <div class="ss-achievement-toast__progress">
                <div id="ss-toast-bar" class="ss-achievement-toast__progress-bar"></div>
            </div>
        `;
        
        document.body.appendChild(toast);

        // Animate progress bar
        const bar = toast.querySelector('#ss-toast-bar');
        if (bar) {
            bar.style.transition = 'transform 8s linear';
            setTimeout(() => {
                bar.style.transform = 'scaleX(0)';
            }, 100);
        }

        // Auto-close
        setTimeout(() => {
            toast.classList.add('ss-achievement-toast--leaving');
            setTimeout(() => toast.remove(), 400);
        }, 8000);
    }

    document.addEventListener('DOMContentLoaded', startScan);
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>