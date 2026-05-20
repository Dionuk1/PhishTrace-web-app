<?php
// General helper functions and URL risk analysis engine.

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

/**
 * Build base URL like "/phishtrace" regardless of current script depth.
 */
/**
 * APP BASE URL
 * Determines the root directory of the application dynamically.
 * Useful for building paths that work across different server environments.
 */
function appBaseUrl(): string
{
    static $base = null;

    if ($base !== null) {
        return $base;
    }

    $scriptName = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? ''));
    if (str_contains($scriptName, '/admin/')) {
        // Handle admin subdirectory specifically
        $base = (string) preg_replace('#/admin/.*$#', '', $scriptName);
    } else {
        $base = str_replace('\\', '/', dirname($scriptName));
    }

    if ($base === '.' || $base === '/') {
        $base = '';
    }

    return rtrim($base, '/');
}

/**
 * APP PATH
 * Constructs an absolute internal URL for resources or pages.
 */
function appPath(string $path = ''): string
{
    $cleanPath = ltrim($path, '/');
    $base = appBaseUrl();
    return $base . ($cleanPath !== '' ? '/' . $cleanPath : '');
}

/**
 * OUTPUT ESCAPING (e)
 * Prevents XSS (Cross-Site Scripting) by converting special characters 
 * into HTML entities before rendering them in the browser.
 */
function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

/**
 * REDIRECT
 * Sends the user to a new location within the app and terminates execution.
 */
function redirect(string $path): void
{
    header('Location: ' . appPath($path));
    exit;
}

/**
 * FLASH MESSAGES
 * Sets a temporary message in the session to be displayed after a redirect.
 */
function setFlash(string $message, string $type = 'info'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

/**
 * GET FLASH
 * Retrieves and clears the flash message from the session.
 */
function getFlash(): ?array
{
    if (!isset($_SESSION['flash'])) {
        return null;
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $flash;
}

/**
 * CSRF TOKEN GENERATION
 * Generates a cryptographically secure random token for form protection.
 */
function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * CSRF TOKEN VERIFICATION
 * Validates a submitted token against the one stored in the session.
 * This is non-destructive (no unset) to allow reliable multi-step workflows.
 */
function verifyCsrfToken(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }

    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * INPUT SANITIZATION
 * Cleans user-submitted URLs to prevent injection and malformed requests.
 */
function sanitizeUrlInput(string $url): string
{
    return trim(filter_var($url, FILTER_SANITIZE_URL));
}

/**
 * DOMAIN NORMALIZATION
 * Extracts the primary domain from a URL (e.g., "https://www.google.com/search" -> "google.com").
 * Used for comparing against blacklists/whitelists.
 */
function normalizeDomain(string $host): string
{
    $host = strtolower(trim($host));
    $host = preg_replace('#^https?://#', '', $host);
    $host = preg_replace('#/.*$#', '', $host);
    $host = rtrim($host, '.');
    if (str_starts_with($host, 'www.')) {
        $host = substr($host, 4);
    }
    return $host;
}

/**
 * RISK SCORE TO STATUS
 * Maps a numerical risk score (0-100) to a user-friendly status label.
 */
function scoreToStatus(int $score): string
{
    if ($score <= 20) {
        return 'Safe';
    }
    if ($score <= 49) {
        return 'Suspicious';
    }
    return 'Dangerous';
}

/**
 * STATUS BADGE CLASS
 * Returns the CSS class for status badges (Bootstrap style).
 */
function statusBadgeClass(string $status): string
{
    return match ($status) {
        'Safe' => 'success',
        'Suspicious' => 'warning',
        'Dangerous' => 'danger',
        default => 'secondary',
    };
}

/**
 * STATUS DISPLAY LABEL
 * Formats status strings for the user interface.
 */
function statusDisplayLabel(string $status): string
{
    return match ($status) {
        'Dangerous' => 'High Risk',
        default => $status,
    };
}

/**
 * ENVIRONMENT VALUES
 * Safely retrieves configuration variables from various server sources (ENV, SERVER, etc.).
 */
function envValue(string $key, ?string $default = null): ?string
{
    $value = getenv($key);
    if ($value !== false && $value !== '') {
        return (string) $value;
    }

    if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
        return (string) $_ENV[$key];
    }

    if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
        return (string) $_SERVER[$key];
    }

    return $default;
}

/**
 * CHECKPHISH API: POST REQUEST
 * Low-level helper to communicate with the Bolster/CheckPhish API.
 */
function checkPhishPostJson(string $endpoint, array $payload, int $timeout = 12): array
{
    if (!function_exists('curl_init')) {
        return [
            'ok' => false,
            'error' => 'cURL is not available for CheckPhish API requests.',
            'status_code' => 0,
            'data' => null,
        ];
    }

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    ]);

    $rawResponse = curl_exec($ch);
    $curlError = curl_error($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    unset($ch);

    $decoded = is_string($rawResponse) && $rawResponse !== ''
        ? json_decode($rawResponse, true)
        : null;

    if ($statusCode >= 400 || !is_array($decoded)) {
        $errorPayload = is_array($decoded['error'] ?? null) ? $decoded['error'] : [];
        $apiError = is_array($decoded)
            ? (string) ($decoded['message'] ?? $errorPayload['message'] ?? $errorPayload['status'] ?? '')
            : '';

        return [
            'ok' => false,
            'error' => $apiError !== '' ? $apiError : ($curlError !== '' ? $curlError : 'CheckPhish API request failed.'),
            'status_code' => $statusCode,
            'data' => $decoded,
        ];
    }

    return [
        'ok' => true,
        'error' => null,
        'status_code' => $statusCode,
        'data' => $decoded,
    ];
}

/**
 * CHECKPHISH API: FULL SCAN FLOW
 * Handles submission and polling to get a final security disposition for a URL.
 */
function fetchCheckPhishAnalysis(string $url): array
{
    $apiKey = envValue('CHECKPHISH_API_KEY', 'frjk6y11c3pn7srlxzn6s2j44gjiv06189zyxn0zdrcqxxa86prw3rsb01exqsk2');
    if ($apiKey === null || $apiKey === '') {
        return [
            'ok' => false,
            'error' => 'CHECKPHISH_API_KEY is not configured.',
        ];
    }

    $scan = checkPhishPostJson('https://developers.bolster.ai/api/neo/scan', [
        'apiKey' => $apiKey,
        'urlInfo' => ['url' => $url],
        'scanType' => 'quick',
    ]);

    if (!$scan['ok']) {
        return [
            'ok' => false,
            'error' => $scan['error'],
        ];
    }

    $scanData = is_array($scan['data']) ? $scan['data'] : [];
    $jobId = (string) ($scanData['jobID'] ?? $scanData['jobId'] ?? $scanData['job_id'] ?? '');
    if ($jobId === '') {
        return [
            'ok' => false,
            'error' => 'CheckPhish did not return a jobID.',
        ];
    }

    $latestStatus = null;
    for ($attempt = 0; $attempt < 4; $attempt++) {
        sleep(3);

        $status = checkPhishPostJson('https://developers.bolster.ai/api/neo/scan/status', [
            'apiKey' => $apiKey,
            'jobID' => $jobId,
            'insights' => true,
        ], 15);

        if (!$status['ok']) {
            return [
                'ok' => false,
                'job_id' => $jobId,
                'error' => $status['error'],
            ];
        }

        $latestStatus = is_array($status['data']) ? $status['data'] : [];
        if (strtoupper((string) ($latestStatus['status'] ?? '')) === 'DONE') {
            break;
        }
    }

    if (!is_array($latestStatus)) {
        return [
            'ok' => false,
            'job_id' => $jobId,
            'error' => 'CheckPhish status response was empty.',
        ];
    }

    $categories = [];
    $confidence = null;
    foreach (($latestStatus['categories'] ?? []) as $category) {
        if (is_array($category)) {
            if (isset($category['score']) && is_numeric($category['score'])) {
                $confidence = max((float) ($confidence ?? 0), (float) $category['score']);
            }

            $categories[] = (string) ($category['category'] ?? $category['name'] ?? 'Uncategorized');
            continue;
        }

        if (is_string($category) && $category !== '') {
            $categories[] = $category;
        }
    }

    return [
        'ok' => true,
        'job_id' => $jobId,
        'status' => (string) ($latestStatus['status'] ?? 'PENDING'),
        'disposition' => (string) ($latestStatus['disposition'] ?? 'unknown'),
        'brand' => (string) ($latestStatus['brand'] ?? ''),
        'confidence' => $confidence,
        'resolved' => (bool) ($latestStatus['resolved'] ?? false),
        'screenshot_path' => (string) ($latestStatus['screenshot_path'] ?? ''),
        'insights' => (string) ($latestStatus['insights'] ?? ''),
        'scan_time_ms' => !empty($latestStatus['scan_start_ts']) && !empty($latestStatus['scan_end_ts'])
            ? max(0, (int) $latestStatus['scan_end_ts'] - (int) $latestStatus['scan_start_ts'])
            : null,
        'categories' => array_values(array_unique(array_filter($categories))),
        'raw' => $latestStatus,
    ];
}

/**
 * SSRF PROTECTION
 * Prevents the server from making requests to internal/private IP ranges.
 */
function isSsrfBlockedUrl(string $url): bool
{
    $host = (string) parse_url($url, PHP_URL_HOST);
    if ($host === '') {
        return true;
    }

    $resolvedIp = gethostbyname($host);
    if ($resolvedIp === $host || filter_var($resolvedIp, FILTER_VALIDATE_IP) === false) {
        return true;
    }

    return filter_var(
        $resolvedIp,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

/**
 * Fetch remote HTML for live content inspection.
 */
function fetchRemoteHtml(string $url): array
{
    if (isSsrfBlockedUrl($url)) {
        return [
            'ok' => false,
            'html' => '',
            'error' => 'Unable to fetch HTML content.',
            'status_code' => 0,
            'content_type' => '',
        ];
    }

    $userAgent = 'PhishTrace-AI-Security-Assistant/1.0';
    $headers = [
        'User-Agent: ' . $userAgent,
        'Accept: text/html,application/xhtml+xml',
    ];

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_USERAGENT => $userAgent,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body = curl_exec($ch);
        $error = curl_error($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        unset($ch);

        if (is_string($body) && $body !== '') {
            return [
                'ok' => true,
                'html' => $body,
                'error' => null,
                'status_code' => $statusCode,
                'content_type' => $contentType,
            ];
        }

        return [
            'ok' => false,
            'html' => '',
            'error' => $error !== '' ? $error : 'Unable to fetch HTML content.',
            'status_code' => $statusCode,
            'content_type' => $contentType,
        ];
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'follow_location' => 1,
            'max_redirects' => 3,
            'header' => implode("\r\n", $headers),
        ],
    ]);

    $body = @file_get_contents($url, false, $context);
    if (is_string($body) && $body !== '') {
        return [
            'ok' => true,
            'html' => $body,
            'error' => null,
            'status_code' => 200,
            'content_type' => '',
        ];
    }

    $lastError = error_get_last();

    return [
        'ok' => false,
        'html' => '',
        'error' => $lastError['message'] ?? 'Unable to fetch HTML content.',
        'status_code' => 0,
        'content_type' => '',
    ];
}

/**
 * Placeholder domain age estimation until WHOIS integration is added.
 */
function estimateDomainAge(string $host): array
{
    $signals = 0;

    if (substr_count($host, '-') >= 2) {
        $signals++;
    }

    if (count(array_filter(explode('.', $host))) > 3) {
        $signals++;
    }

    if (preg_match('/\d/', $host) === 1) {
        $signals++;
    }

    if ($signals >= 2) {
        return [
            'label' => 'Recent / unknown (placeholder estimate)',
            'days' => 30,
            'risk_points' => 12,
            'reason' => 'Domain appears recently created or disposable based on placeholder heuristics.',
        ];
    }

    return [
        'label' => 'Established / unknown (placeholder estimate)',
        'days' => 365,
        'risk_points' => 0,
        'reason' => 'Domain age could not be verified live, but placeholder heuristics did not flag it as newly created.',
    ];
}

/**
 * Scan fetched HTML for phishing indicators.
 */
function analyzeHtmlThreatIndicators(string $html): array
{
    $normalized = strtolower($html);
    $text = strtolower(trim(preg_replace('/\s+/', ' ', strip_tags($html)) ?? ''));

    $suspiciousKeywords = [
        'airdrop',
        'bonus',
        'verify account',
        'free crypto',
        'claim reward',
    ];
    $brandKeywords = [
        'paypal',
        'binance',
        'facebook',
        'instagram',
    ];
    $walletKeywords = [
        'metamask',
        'wallet connect',
        'connect wallet',
    ];

    $foundSuspicious = [];
    foreach ($suspiciousKeywords as $keyword) {
        if (str_contains($text, $keyword) || str_contains($normalized, $keyword)) {
            $foundSuspicious[] = $keyword;
        }
    }

    $foundBrands = [];
    foreach ($brandKeywords as $keyword) {
        if (str_contains($text, $keyword) || str_contains($normalized, $keyword)) {
            $foundBrands[] = ucfirst($keyword);
        }
    }

    $foundWallets = [];
    foreach ($walletKeywords as $keyword) {
        if (str_contains($text, $keyword) || str_contains($normalized, $keyword)) {
            $foundWallets[] = $keyword;
        }
    }

    $hasPasswordField = preg_match('/<input[^>]+type=["\']?password["\']?/i', $html) === 1;

    return [
        'login_form_detected' => $hasPasswordField,
        'suspicious_keywords' => array_values(array_unique($foundSuspicious)),
        'brand_mentions' => array_values(array_unique($foundBrands)),
        'wallet_prompts' => array_values(array_unique($foundWallets)),
    ];
}

/**
 * Turn structured indicators into dashboard rows.
 */
function buildThreatIndicators(array $analysis): array
{
    return [
        ['label' => 'Domain age', 'value' => (string) $analysis['domain_age']['label']],
        ['label' => 'SSL status', 'value' => (string) $analysis['ssl_status']['label']],
        ['label' => 'Login form detected', 'value' => $analysis['html_analysis']['login_form_detected'] ? 'Yes' : 'No'],
        [
            'label' => 'Suspicious keywords detected',
            'value' => $analysis['html_analysis']['suspicious_keywords'] !== []
                ? implode(', ', $analysis['html_analysis']['suspicious_keywords'])
                : 'None',
        ],
        [
            'label' => 'Brand mentions detected',
            'value' => $analysis['html_analysis']['brand_mentions'] !== []
                ? implode(', ', $analysis['html_analysis']['brand_mentions'])
                : 'None',
        ],
        [
            'label' => 'Crypto wallet prompts detected',
            'value' => $analysis['html_analysis']['wallet_prompts'] !== []
                ? implode(', ', $analysis['html_analysis']['wallet_prompts'])
                : 'None',
        ],
    ];
}

/**
 * Build concise threat items for the dashboard alert list.
 */
function buildThreatAlertItems(array $analysis): array
{
    $items = [];

    if (!($analysis['ssl_status']['is_secure'] ?? false)) {
        $items[] = [
            'icon' => '!',
            'tone' => 'danger',
            'text' => 'No HTTPS detected',
        ];
    }

    if (!empty($analysis['domain_age']['risk_points'])) {
        $items[] = [
            'icon' => '!',
            'tone' => 'warning',
            'text' => 'Recently created or unverified domain signal detected',
        ];
    }

    if (!empty($analysis['html_analysis']['login_form_detected'])) {
        $items[] = [
            'icon' => '!',
            'tone' => 'danger',
            'text' => 'Login form detected',
        ];
    }

    if (!empty($analysis['html_analysis']['brand_mentions'])) {
        $items[] = [
            'icon' => '!',
            'tone' => 'danger',
            'text' => 'Brand impersonation indicators detected: ' . implode(', ', $analysis['html_analysis']['brand_mentions']),
        ];
    }

    if (!empty($analysis['html_analysis']['suspicious_keywords'])) {
        $items[] = [
            'icon' => '!',
            'tone' => 'warning',
            'text' => 'Suspicious phishing keywords detected: ' . implode(', ', $analysis['html_analysis']['suspicious_keywords']),
        ];
    }

    if (!empty($analysis['html_analysis']['wallet_prompts'])) {
        $items[] = [
            'icon' => '!',
            'tone' => 'warning',
            'text' => 'Crypto wallet prompts detected: ' . implode(', ', $analysis['html_analysis']['wallet_prompts']),
        ];
    }

    if ($items === []) {
        $items[] = [
            'icon' => 'OK',
            'tone' => 'safe',
            'text' => 'No major phishing indicators were detected in this scan',
        ];
    }

    return $items;
}

/**
 * Return progress bar color token for the current risk level.
 */
function riskBarTone(string $status): string
{
    return match ($status) {
        'Safe' => 'safe',
        'Suspicious' => 'warning',
        'Dangerous' => 'danger',
        default => 'warning',
    };
}

function checkPhishRiskLevel(array $analysis): string
{
    $checkPhish = is_array($analysis['checkphish'] ?? null) ? $analysis['checkphish'] : [];
    $disposition = strtolower((string) ($checkPhish['disposition'] ?? ''));

    if ($disposition === 'clean') {
        return 'Safe';
    }

    if (in_array($disposition, ['phish', 'phishing', 'malicious', 'scam', 'likely_phish', 'hacked_website', 'cryptojacking'], true)) {
        return 'Dangerous';
    }

    if ($disposition === 'suspicious' || $disposition === 'unknown' || $disposition === '') {
        return 'Suspicious';
    }

    return 'Suspicious';
}

function formatCheckPhishConfidence($confidence): string
{
    if ($confidence === null || !is_numeric($confidence)) {
        return 'Not provided';
    }

    $confidence = (float) $confidence;

    if ($confidence <= 1) {
        return (string) round($confidence * 100) . '%';
    }

    return (string) round($confidence) . '%';
}

/**
 * AI SUMMARY BUILDER
 * Compiles a structured textual security report from scan data.
 */
function buildFallbackAiReport(array $analysis): string
{
    $checkPhish = is_array($analysis['checkphish'] ?? null) ? $analysis['checkphish'] : [];
    $riskLevel = checkPhishRiskLevel($analysis);
    $reasons = [];

    if (empty($checkPhish['ok'])) {
        $reasons[] = '- CheckPhish scan was unavailable: ' . (string) ($checkPhish['error'] ?? 'unknown error');
        foreach ($analysis['reasons'] as $reason) {
            $reasons[] = '- ' . preg_replace('/\s*\(\+\d+\)$/', '', $reason);
        }
    } else {
        $disposition = (string) ($checkPhish['disposition'] ?? 'unknown');
        $reasons[] = '- CheckPhish disposition: ' . $disposition;
        $reasons[] = '- Confidence: ' . formatCheckPhishConfidence($checkPhish['confidence'] ?? null);

        if (($checkPhish['brand'] ?? '') !== '') {
            $reasons[] = '- Brand signal: ' . (string) $checkPhish['brand'];
        }

        if (($checkPhish['categories'] ?? []) !== []) {
            $reasons[] = '- Categories: ' . implode(', ', $checkPhish['categories']);
        }

        $reasons[] = '- URL resolution: ' . (!empty($checkPhish['resolved']) ? 'resolved by CheckPhish' : 'not resolved by CheckPhish');
    }

    $recommendations = [
        '- Do not enter credentials on the scanned page until the domain is independently verified.',
        '- Do not connect crypto wallets or approve browser wallet prompts on untrusted sites.',
        '- Confirm the brand domain manually and navigate to it directly instead of using the scanned link.',
    ];

    if ($riskLevel === 'Dangerous') {
        $recommendations[] = '- Treat this URL as unsafe and avoid opening it on a primary device or network.';
    } elseif ($riskLevel === 'Suspicious') {
        $recommendations[] = '- Verify the sender and domain before trusting this link.';
    } else {
        $recommendations[] = '- Continue checking for cloned login pages, unexpected downloads, or unusual payment requests.';
    }

    $summary = empty($checkPhish['ok'])
        ? 'CheckPhish could not complete the scan, so the current local indicators are shown as a fallback.'
        : 'CheckPhish classified this URL as ' . (string) ($checkPhish['disposition'] ?? 'unknown') . '.';

    return implode("\n", [
        'AI Security Assistant Report',
        '',
        'Risk Level: ' . $riskLevel,
        '',
        'Threat Summary:',
        '- ' . $summary,
        '',
        'Reasons:',
        implode("\n", $reasons),
        '',
        'Recommendations:',
        implode("\n", $recommendations),
    ]);
}

/**
 * Convert report text into presentable HTML.
 */
function renderAiReportHtml(string $report): string
{
    $lines = preg_split('/\R/', trim($report)) ?: [];
    $html = [];
    $listOpen = false;

    foreach ($lines as $line) {
        $trimmed = trim($line);

        if ($trimmed === '') {
            if ($listOpen) {
                $html[] = '</ul>';
                $listOpen = false;
            }
            continue;
        }

        if (str_starts_with($trimmed, '- ')) {
            if (!$listOpen) {
                $html[] = '<ul class="ss-ai-summary-list">';
                $listOpen = true;
            }
            $html[] = '<li>' . e(substr($trimmed, 2)) . '</li>';
            continue;
        }

        if ($listOpen) {
            $html[] = '</ul>';
            $listOpen = false;
        }

        if (str_ends_with($trimmed, ':')) {
            $html[] = '<h4 class="ss-ai-summary-heading">' . e(rtrim($trimmed, ':')) . '</h4>';
            continue;
        }

        $html[] = '<p class="ss-ai-summary-text">' . e($trimmed) . '</p>';
    }

    if ($listOpen) {
        $html[] = '</ul>';
    }

    return implode('', $html);
}

/**
 * AI ASSISTANT DISPATCHER
 * Generates the security report, ensuring API results are present.
 */
function generateAiSecurityAssistantReport(array $analysis): array
{
    if (empty($analysis['checkphish']) && !empty($analysis['url'])) {
        $analysis['checkphish'] = fetchCheckPhishAnalysis((string) $analysis['url']);
    }

    return [
        'text' => buildFallbackAiReport($analysis),
        'source' => 'checkphish',
        'error' => !empty($analysis['checkphish']['ok']) ? null : (string) ($analysis['checkphish']['error'] ?? 'CheckPhish API request failed.'),
    ];
}

/**
 * Analyze submitted URL with rule-based phishing heuristics.
 * Returns score, status, domain and detailed reasons.
 */
function analyzeUrl(string $inputUrl, PDO $pdo): array
{
    $riskScore = 0;
    $reasons = [];
    $details = [];
    $normalizedUrl = sanitizeUrlInput($inputUrl);

    if (!filter_var($normalizedUrl, FILTER_VALIDATE_URL)) {
        return [
            'valid' => false,
            'url' => $normalizedUrl,
            'domain' => '',
            'risk_score' => 0,
            'status' => 'Suspicious',
            'reasons' => ['Invalid URL format. Please include http:// or https://'],
            'details' => ['URL did not pass FILTER_VALIDATE_URL validation.'],
        ];
    }

    $parts = parse_url($normalizedUrl);
    $host = normalizeDomain((string) ($parts['host'] ?? ''));
    $scheme = strtolower($parts['scheme'] ?? '');
    $path = strtolower(($parts['path'] ?? '') . '?' . ($parts['query'] ?? ''));
    $fullLower = strtolower($normalizedUrl);
    $fetch = fetchRemoteHtml($normalizedUrl);
    $htmlAnalysis = analyzeHtmlThreatIndicators($fetch['html']);
    $domainAge = estimateDomainAge($host);
    $sslStatus = [
        'is_secure' => $scheme === 'https',
        'label' => $scheme === 'https' ? 'Valid (HTTPS)' : 'Invalid (HTTP / not encrypted)',
    ];

    // Rule 1: no HTTPS
    if ($scheme !== 'https') {
        $riskScore += 20;
        $reasons[] = 'URL does not use HTTPS (+20)';
        $details[] = 'HTTPS encrypts traffic and helps reduce interception risks.';
    }

    // Rule 2: long URL
    if (strlen($normalizedUrl) > 75) {
        $riskScore += 10;
        $reasons[] = 'URL is unusually long (+10)';
        $details[] = 'Scam links often hide intent in very long URLs.';
    }

    // Rule 3: suspicious keywords in the URL itself
    $keywords = ['login', 'verify', 'free', 'claim', 'gift', 'bonus', 'urgent', 'reset', 'password', 'wallet', 'bank'];
    $foundKeywords = [];
    foreach ($keywords as $word) {
        if (str_contains($fullLower, $word)) {
            $foundKeywords[] = $word;
        }
    }
    if ($foundKeywords !== []) {
        $riskScore += 15;
        $reasons[] = 'Suspicious keyword(s): ' . implode(', ', array_unique($foundKeywords)) . ' (+15)';
        $details[] = 'Attackers frequently use urgency and account-related words to trick users.';
    }

    // Rule 4: excessive hyphens in host
    if (substr_count($host, '-') >= 3) {
        $riskScore += 10;
        $reasons[] = 'Domain has excessive hyphens (+10)';
        $details[] = 'Many phishing domains use several hyphens to imitate trusted brands.';
    }

    // Rule 5: too many subdomains
    $labels = array_values(array_filter(explode('.', $host)));
    if (count($labels) > 3) {
        $riskScore += 15;
        $reasons[] = 'Too many subdomains detected (+15)';
        $details[] = 'Very deep subdomains can be used to confuse users.';
    }

    // Rule 6: IP address instead of normal domain
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $riskScore += 25;
        $reasons[] = 'URL uses an IP address instead of a domain (+25)';
        $details[] = 'Legitimate social platforms usually rely on recognizable domain names.';
    }

    // Rule 7: @ symbol
    if (str_contains($normalizedUrl, '@')) {
        $riskScore += 20;
        $reasons[] = 'URL contains @ symbol (+20)';
        $details[] = '@ can hide the real destination in a deceptive URL.';
    }

    // Rule 9: placeholder domain age signal
    if ($domainAge['risk_points'] > 0) {
        $riskScore += (int) $domainAge['risk_points'];
        $reasons[] = 'Domain age appears recent based on placeholder analysis (+' . (int) $domainAge['risk_points'] . ')';
        $details[] = $domainAge['reason'];
    }

    // Rule 10: blacklist lookup
    $isBlacklisted = false;
    if ($host !== '') {
        $stmt = $pdo->prepare(
            "SELECT domain, reason FROM blacklist_domains
             WHERE :host_exact = domain OR :host_sub LIKE CONCAT('%.', domain)
             LIMIT 1"
        );
        $stmt->execute([
            'host_exact' => $host,
            'host_sub' => $host,
        ]);
        $blacklistRow = $stmt->fetch();
        if ($blacklistRow) {
            $isBlacklisted = true;
            $riskScore += 50;
            $reasons[] = 'Domain appears on blacklist (+50)';
            $details[] = 'Blacklist reason: ' . ($blacklistRow['reason'] ?: 'Known malicious domain');
        }
    }

    // Rule 11: live HTML indicators
    if ($fetch['ok'] && $htmlAnalysis['login_form_detected']) {
        $riskScore += 18;
        $reasons[] = 'Login form detected in fetched HTML (+18)';
        $details[] = 'Pages requesting passwords are higher risk when combined with impersonation or urgency signals.';
    }

    if ($fetch['ok'] && $htmlAnalysis['suspicious_keywords'] !== []) {
        $riskScore += 15;
        $reasons[] = 'Suspicious phishing keywords found in page content (+15)';
        $details[] = 'Detected keywords: ' . implode(', ', $htmlAnalysis['suspicious_keywords']);
    }

    if ($fetch['ok'] && $htmlAnalysis['brand_mentions'] !== []) {
        $riskScore += 12;
        $reasons[] = 'Potential brand impersonation keywords detected (+12)';
        $details[] = 'Detected brands: ' . implode(', ', $htmlAnalysis['brand_mentions']);
    }

    if ($fetch['ok'] && $htmlAnalysis['wallet_prompts'] !== []) {
        $riskScore += 18;
        $reasons[] = 'Crypto wallet connection prompts detected (+18)';
        $details[] = 'Detected wallet-related prompts: ' . implode(', ', $htmlAnalysis['wallet_prompts']);
    }

    if (!$fetch['ok']) {
        $details[] = 'Live HTML could not be fetched for content inspection: ' . ($fetch['error'] ?? 'Unknown error');
    }

    // Optional informational rule: whitelist lookup (no score increase).
    if ($host !== '' && !$isBlacklisted) {
        $stmt = $pdo->prepare(
            "SELECT domain FROM whitelist_domains
             WHERE :host_exact = domain OR :host_sub LIKE CONCAT('%.' , domain)
             LIMIT 1"
        );
        $stmt->execute(['host_exact' => $host, 'host_sub' => $host]);
        if ($stmt->fetch()) {
            $details[] = 'Domain exists in whitelist data.';
        }
    }

    if ($reasons === []) {
        $reasons[] = 'No suspicious indicators triggered.';
        $details[] = 'The scan engine found no matching high-risk patterns in this URL.';
    }

    $riskScore = max(0, min(100, $riskScore));

    $analysis = [
        'valid' => true,
        'url' => $normalizedUrl,
        'domain' => $host,
        'risk_score' => $riskScore,
        'status' => scoreToStatus($riskScore),
        'reasons' => $reasons,
        'details' => $details,
        'analyzed_path' => $path,
        'domain_age' => $domainAge,
        'ssl_status' => $sslStatus,
        'html_analysis' => $htmlAnalysis,
        'fetch' => $fetch,
    ];

    $analysis['threat_indicators'] = buildThreatIndicators($analysis);
    $analysis['threat_alerts'] = buildThreatAlertItems($analysis);

    return $analysis;
}

/**
 * Points earned by scan outcome.
 */
function securityPointsByStatus(string $status): int
{
    return match ($status) {
        'Safe' => 10,
        'Suspicious' => 3,
        'Dangerous' => 1,
        default => 0,
    };
}

/**
 * Unlock a seeded achievement for a user if it is not already unlocked.
 */
function unlockAchievementBySlug(int $userId, string $slug, PDO $pdo): void
{
    if (!isTableUsable($pdo, 'achievements') || !isTableUsable($pdo, 'user_achievements')) {
        return;
    }

    $stmt = $pdo->prepare(
        'INSERT INTO user_achievements (user_id, achievement_id)
         SELECT :insert_user_id, a.id
         FROM achievements a
         WHERE a.slug = :slug
           AND NOT EXISTS (
               SELECT 1
               FROM user_achievements ua
               WHERE ua.user_id = :lookup_user_id
                 AND ua.achievement_id = a.id
           )'
    );
    $stmt->execute([
        'insert_user_id' => $userId,
        'lookup_user_id' => $userId,
        'slug' => $slug,
    ]);
}

/**
 * Evaluate and unlock eligible achievements for a user.
 */
function awardUserAchievements(int $userId, PDO $pdo): void
{
    if (!isTableUsable($pdo, 'achievements') || !isTableUsable($pdo, 'user_achievements')) {
        return;
    }

    $scanCountStmt = $pdo->prepare('SELECT COUNT(*) FROM scans WHERE user_id = :user_id');
    $scanCountStmt->execute(['user_id' => $userId]);
    $scanCount = (int) $scanCountStmt->fetchColumn();

    $safeScanStmt = $pdo->prepare("SELECT COUNT(*) FROM scans WHERE user_id = :user_id AND status = 'Safe'");
    $safeScanStmt->execute(['user_id' => $userId]);
    $safeScanCount = (int) $safeScanStmt->fetchColumn();

    $scoreStmt = $pdo->prepare('SELECT COALESCE(security_score, 0) FROM users WHERE id = :id LIMIT 1');
    $scoreStmt->execute(['id' => $userId]);
    $securityScore = (int) $scoreStmt->fetchColumn();

    $rules = [
        'first_scan' => $scanCount >= 1,
        'triple_scan' => $scanCount >= 3,
        'ten_scans' => $scanCount >= 10,
        'safe_streak' => $safeScanCount >= 5,
        'score_50' => $securityScore >= 50,
        'score_100' => $securityScore >= 100,
    ];

    foreach ($rules as $slug => $isUnlocked) {
        if ($isUnlocked) {
            unlockAchievementBySlug($userId, $slug, $pdo);
        }
    }
}

/**
 * Load compact achievement notification data for the navbar.
 */
function getUserAchievementNotificationData(int $userId, PDO $pdo): array
{
    $empty = [
        'latest_unlock' => null,
        'total_achievements' => 0,
        'total_points' => 0,
        'achievements' => [],
    ];

    if (!isTableUsable($pdo, 'achievements') || !isTableUsable($pdo, 'user_achievements')) {
        return $empty;
    }

    awardUserAchievements($userId, $pdo);

    $listStmt = $pdo->prepare(
        'SELECT a.title, a.description, a.points, ua.unlocked_at
         FROM user_achievements ua
         INNER JOIN achievements a ON a.id = ua.achievement_id
         WHERE ua.user_id = :user_id
         ORDER BY ua.unlocked_at DESC, ua.id DESC'
    );
    $listStmt->execute(['user_id' => $userId]);
    $achievements = $listStmt->fetchAll() ?: [];

    return [
        'latest_unlock' => $achievements[0] ?? null,
        'total_achievements' => count($achievements),
        'total_points' => array_sum(array_map(
            static fn (array $achievement): int => (int) ($achievement['points'] ?? 0),
            $achievements
        )),
        'achievements' => $achievements,
    ];
}

/**
 * Check whether a user record exists.
 */
function userExists(PDO $pdo, int $userId): bool
{
    if ($userId <= 0 || !isTableUsable($pdo, 'users')) {
        return false;
    }

    $stmt = $pdo->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $userId]);
    return (bool) $stmt->fetchColumn();
}

/**
 * Save scan result to database for history.
 * Returns the ID of the new or existing (throttled) scan.
 */
function saveScan(int $userId, string $url, string $domain, int $riskScore, string $status, array $reasons, PDO $pdo): int
{
    /**
     * DUPLICATE SCAN & POINT PROTECTION (Throttle)
     * Checks if the user recently scanned this exact URL.
     */
    $scanTimestampColumn = tableHasColumn($pdo, 'scans', 'created_at')
        ? 'created_at'
        : (tableHasColumn($pdo, 'scans', 'scanned_at') ? 'scanned_at' : null);

    $recentSql = "SELECT id FROM scans WHERE user_id = :uid AND url = :url";
    if ($scanTimestampColumn !== null) {
        $recentSql .= " AND {$scanTimestampColumn} > DATE_SUB(NOW(), INTERVAL 5 MINUTE)";
    }
    $recentSql .= ' LIMIT 1';

    $recentStmt = $pdo->prepare($recentSql);
    $recentStmt->execute(['uid' => $userId, 'url' => $url]);
    $existingId = $recentStmt->fetchColumn();

    if ($existingId) {
        return (int) $existingId;
    }

    $payload = [
        'user_id' => $userId,
        'url' => $url,
        'domain' => $domain,
        'risk_score' => $riskScore,
        'status' => $status,
        'reasons' => json_encode($reasons, JSON_UNESCAPED_UNICODE),
    ];

    if (tableHasColumn($pdo, 'scans', 'domain')) {
        $stmt = $pdo->prepare(
            'INSERT INTO scans (user_id, url, domain, risk_score, status, reasons)
             VALUES (:user_id, :url, :domain, :risk_score, :status, :reasons)'
        );
    } else {
        unset($payload['domain']);
        $stmt = $pdo->prepare(
            'INSERT INTO scans (user_id, url, risk_score, status, reasons)
             VALUES (:user_id, :url, :risk_score, :status, :reasons)'
        );
    }

    $stmt->execute($payload);
    $newScanId = (int) $pdo->lastInsertId();

    if (tableHasColumn($pdo, 'users', 'security_score')) {
        $scorePoints = securityPointsByStatus($status);

        if ($scorePoints > 0) {
            $scoreStmt = $pdo->prepare(
                'UPDATE users SET security_score = COALESCE(security_score, 0) + :points WHERE id = :id'
            );
            $scoreStmt->execute([
                'points' => $scorePoints,
                'id' => $userId,
            ]);
        }
    }

    awardUserAchievements($userId, $pdo);
    
    return $newScanId;
}

/**
 * Suggestions shown after each scan.
 */
function socialSafetyRecommendations(): array
{
    return [
        'Do not enter passwords on links received by DM, SMS, or unknown emails.',
        'Enable two-factor authentication on social media accounts.',
        'Verify the domain manually before logging in (check spelling).',
        'Avoid downloading files from unknown sources or urgent messages.',
        'Report suspicious profiles, posts, and links immediately.',
    ];
}


if (!function_exists('setCurrentLanguage')) {
    function setCurrentLanguage(string $lang): void
    {
        $lang = strtolower(trim($lang));
        $_SESSION['lang'] = in_array($lang, ['en', 'sq'], true) ? $lang : 'en';
    }
}

if (!function_exists('currentLanguage')) {
    function currentLanguage(): string
    {
        $lang = (string) ($_SESSION['lang'] ?? 'en');
        return in_array($lang, ['en', 'sq'], true) ? $lang : 'en';
    }
}

if (!function_exists('languageSwitchUrl')) {
    function languageSwitchUrl(string $lang): string
    {
        $lang = strtolower(trim($lang));
        $lang = in_array($lang, ['en', 'sq'], true) ? $lang : 'en';
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $parts = parse_url($uri) ?: [];
        $path = (string) ($parts['path'] ?? '/');
        $query = [];
        if (!empty($parts['query'])) {
            parse_str((string) $parts['query'], $query);
        }
        $query['lang'] = $lang;
        return $path . '?' . http_build_query($query);
    }
}

if (!function_exists('translateResult')) {
    function translateResult(string $en, string $sq, ?string $lang = null): string
    {
        $selected = $lang !== null ? strtolower(trim((string) $lang)) : currentLanguage();
        $selected = in_array($selected, ['en', 'sq'], true) ? $selected : 'en';

        return $selected === 'sq' ? (string) $sq : (string) $en;
    }
}

if (!function_exists('tr')) {
    function tr(string $en, string $sq): string
    {
        return translateResult($en, $sq);
    }
}

if (!function_exists('t')) {
    function t(string $key): string
    {
        static $dict = null;

        if ($dict === null) {
            $dict = loadTranslations();
        }

        $lang = currentLanguage();
        $value = $dict[$lang][$key] ?? null;
        if ($value !== null) {
            return $value;
        }

        return $dict['en'][$key] ?? ucwords(str_replace('_', ' ', $key));
    }
}

if (!function_exists('loadTranslations')) {
    function loadTranslations(): array
    {
        $fallback = [
            'en' => [
                'invalid_csrf' => 'Invalid CSRF token.',
                'language_saved' => 'Language saved.',
                'settings' => 'Settings',
                'language_settings' => 'Language Settings',
                'choose_language' => 'Language',
                'home' => 'Home',
                'scan_url' => 'Scan URL',
                'history' => 'History',
                'security_tips' => 'Security Tips',
                'tips_title' => 'Security and Privacy Tips for Social Networks',
                'tips_intro' => 'These tips help reduce phishing, account takeover, and privacy leaks.',
                'tips_empty' => 'No tips found. Import the PhishTrace seed data first.',
                'scan_title' => 'Scan a suspicious link',
                'scan_subtitle' => 'PhishTrace checks the URL, scan indicators, and suspicious patterns before you click.',
                'scan_input_label' => 'URL to scan',
                'scan_placeholder' => 'https://example.com/login',
                'scan_button' => 'Start scan',
                'history_title' => 'Your Scan History',
                'history_new_scan' => 'New Scan',
                'history_empty' => 'No scans found yet. Try your first URL scan.',
                'history_table_date' => 'Date',
                'history_table_url' => 'URL',
                'history_table_score' => 'Score',
                'history_table_status' => 'Status',
                'history_table_reasons' => 'Reasons',
                'history_no_reasons' => 'No reasons stored',
                'home_hero_title' => 'Stay safer on social networks with PhishTrace',
                'home_hero_body' => 'This beginner-friendly web app demonstrates rule-based phishing link detection, privacy awareness, and secure coding basics in PHP.',
                'home_scan_cta' => 'Scan a URL',
                'home_tips_cta' => 'Read Security Tips',
                'home_quick_checks' => 'Quick Security Checks',
                'home_tip_2fa_title' => 'Add 2FA to your accounts',
                'home_tip_2fa_body' => 'Turn on two-factor authentication on every social account.',
                'home_tip_link_title' => 'Check links before clicking',
                'home_tip_link_body' => 'Verify the domain manually before logging in or opening a page.',
                'home_tip_pass_title' => 'Use strong unique passwords',
                'home_tip_pass_body' => 'Avoid reusing the same password across social and email accounts.',
                'home_step_1_title' => '1. Submit Link',
                'home_step_1_body' => 'Paste any URL and run a quick risk analysis using predefined scam indicators.',
                'home_step_2_title' => '2. Understand Risk',
                'home_step_2_body' => 'Get score, status badge, and reasons that explain why a link may be suspicious.',
                'home_step_3_title' => '3. Learn Safe Habits',
                'home_step_3_body' => 'Review privacy and security recommendations for social media usage.',
                'english' => 'English',
                'albanian' => 'Albanian',
                'notifications' => 'Notifications',
                'achievement_unlocked' => 'Achievement unlocked',
                'no_achievements_yet' => 'No achievements yet',
                'achievements_empty_help' => 'Your unlocked achievements will show here.',
                'achievements_empty_cta' => 'Complete scans to unlock achievements and earn points.',
                'total_achievements' => 'Total achievements',
                'total_points' => 'Total points',
                'threat_radar' => 'Threat Radar',
                'register' => 'Register',
                'logout' => 'Logout',
            ],
            'sq' => [
                'invalid_csrf' => 'Token CSRF i pavlefshëm.',
                'language_saved' => 'Gjuha u ruajt.',
                'settings' => 'Cilësimet',
                'language_settings' => 'Cilësimet e gjuhës',
                'choose_language' => 'Gjuha',
                'home' => 'Ballina',
                'scan_url' => 'Skano URL',
                'history' => 'Historiku',
                'security_tips' => 'Këshilla',
                'tips_title' => 'Këshilla për sigurinë dhe privatësinë në rrjetet sociale',
                'tips_intro' => 'Këto këshilla ulin phishing, marrjen e llogarive dhe rrjedhjet e privatësisë.',
                'tips_empty' => 'Nuk u gjetën këshilla. Importo të dhënat fillestare të PhishTrace.',
                'scan_title' => 'Skano një link të dyshimtë',
                'scan_subtitle' => 'PhishTrace kontrollon URL-në, treguesit e skanimit dhe modelet e dyshimta para se të klikosh.',
                'scan_input_label' => 'URL për skanim',
                'scan_placeholder' => 'https://shembull.com/hyrja',
                'scan_button' => 'Nis skanimin',
                'history_title' => 'Historiku i skanimeve',
                'history_new_scan' => 'Skanim i ri',
                'history_empty' => 'Ende nuk ka skanime. Provo skanimin e parë të URL-së.',
                'history_table_date' => 'Data',
                'history_table_url' => 'URL',
                'history_table_score' => 'Rezultati',
                'history_table_status' => 'Statusi',
                'history_table_reasons' => 'Arsyet',
                'history_no_reasons' => 'Nuk ka arsye të ruajtura',
                'home_hero_title' => 'Qëndro më i sigurt në rrjetet sociale me PhishTrace',
                'home_hero_body' => 'Ky aplikacion miqësor për fillestarët demonstron zbulimin e linkeve phishing me rregulla, ndërgjegjësimin për privatësinë dhe bazat e kodimit të sigurt në PHP.',
                'home_scan_cta' => 'Skano një URL',
                'home_tips_cta' => 'Lexo këshillat e sigurisë',
                'home_quick_checks' => 'Kontrolle të shpejta sigurie',
                'home_tip_2fa_title' => 'Shto 2FA në llogaritë e tua',
                'home_tip_2fa_body' => 'Aktivizo autentifikimin me dy faktorë në çdo llogari sociale.',
                'home_tip_link_title' => 'Kontrollo linket para se të klikosh',
                'home_tip_link_body' => 'Verifiko domenin manualisht para se të hysh ose të hapësh një faqe.',
                'home_tip_pass_title' => 'Përdor fjalëkalime të forta unike',
                'home_tip_pass_body' => 'Mos ripërdor të njëjtin fjalëkalim në llogari sociale dhe email.',
                'home_step_1_title' => '1. Dërgo linkun',
                'home_step_1_body' => 'Ngjit çdo URL dhe kryej një analizë të shpejtë me tregues mashtrimi.',
                'home_step_2_title' => '2. Kupto rrezikun',
                'home_step_2_body' => 'Merr rezultat, status dhe arsyet që shpjegojnë pse linku mund të jetë i dyshimtë.',
                'home_step_3_title' => '3. Mëso zakone të sigurta',
                'home_step_3_body' => 'Shiko rekomandimet për privatësi dhe siguri në rrjetet sociale.',
                'english' => 'Anglisht',
                'albanian' => 'Shqip',
                'notifications' => 'Njoftimet',
                'achievement_unlocked' => 'Fitove një arritje',
                'no_achievements_yet' => 'Ende pa arritje',
                'achievements_empty_help' => 'Arritjet e tua do të shfaqen këtu.',
                'achievements_empty_cta' => 'Kryej skanime për të zhbllokuar arritje dhe për të fituar pikë.',
                'total_achievements' => 'Totali i arritjeve',
                'total_points' => 'Totali i pikëve',
                'threat_radar' => 'Radari i Kërcënimeve',
                'register' => 'Regjistrohu',
                'logout' => 'Dil',
            ],
        ];

        $translationDir = realpath(__DIR__ . '/../locales');
        if ($translationDir === false) {
            return $fallback;
        }

        foreach (['en', 'sq'] as $lang) {
            $path = $translationDir . DIRECTORY_SEPARATOR . $lang . '.json';
            if (!is_file($path)) {
                continue;
            }

            $json = file_get_contents($path);
            if ($json === false) {
                continue;
            }

            $loaded = json_decode($json, true);
            if (is_array($loaded)) {
                $fallback[$lang] = array_replace($fallback[$lang], $loaded);
            }
        }

        return $fallback;
    }
}

if (!function_exists('languageFlagUrl')) {
    function languageFlagUrl(string $lang): string
    {
        return strtolower($lang) === 'sq' ? 'https://flagcdn.com/w40/xk.png' : 'https://flagcdn.com/w40/us.png';
    }
}
if (!function_exists('displayStatusLabel')) {
    function displayStatusLabel(string $status): string
    {
        $normalized = strtolower(trim($status));
        return match ($normalized) {
            'success' => 'Success',
            'failed', 'failure', 'danger', 'error' => 'Failed',
            default => ucfirst($status),
        };
    }
}

if (!function_exists('ssBackupDirectory')) {
    function ssBackupDirectory(): string
    {
        $dir = realpath(__DIR__ . '/..') . DIRECTORY_SEPARATOR . 'backups';
        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException('Could not create backups directory.');
        }
        return $dir;
    }
}

if (!function_exists('createUsersBackup')) {
    function createUsersBackup(PDO $pdo, string $label = 'manual'): ?array
    {
        if (!isTableUsable($pdo, 'users')) {
            return null;
        }

        $backupDir = ssBackupDirectory();
        $stamp = date('Ymd_His');
        $safeLabel = preg_replace('/[^a-zA-Z0-9_-]/', '_', $label) ?: 'backup';
        $csvPath = $backupDir . DIRECTORY_SEPARATOR . "users_{$safeLabel}_{$stamp}.csv";

        $rows = $pdo->query('SELECT * FROM users ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $columns = $rows !== [] ? array_keys($rows[0]) : ['id', 'name', 'email', 'password_hash', 'role', 'security_score', 'created_at'];

        $fh = fopen($csvPath, 'wb');
        if ($fh === false) {
            return null;
        }

        fputcsv($fh, $columns);
        foreach ($rows as $row) {
            $line = [];
            foreach ($columns as $col) {
                $line[] = $row[$col] ?? null;
            }
            fputcsv($fh, $line);
        }
        fclose($fh);

        return ['csv' => $csvPath, 'rows' => count($rows)];
    }
}

if (!function_exists('createScansBackup')) {
    function createScansBackup(PDO $pdo, string $label = 'manual'): ?array
    {
        if (!isTableUsable($pdo, 'scans')) {
            return null;
        }

        $backupDir = ssBackupDirectory();
        $stamp = date('Ymd_His');
        $safeLabel = preg_replace('/[^a-zA-Z0-9_-]/', '_', $label) ?: 'backup';
        $csvPath = $backupDir . DIRECTORY_SEPARATOR . "scans_{$safeLabel}_{$stamp}.csv";

        $rows = $pdo->query('SELECT * FROM scans ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $columns = $rows !== [] ? array_keys($rows[0]) : ['id', 'user_id', 'url', 'domain', 'risk_score', 'status', 'reasons', 'scanned_at'];

        $fh = fopen($csvPath, 'wb');
        if ($fh === false) {
            return null;
        }

        fputcsv($fh, $columns);
        foreach ($rows as $row) {
            $line = [];
            foreach ($columns as $col) {
                $line[] = $row[$col] ?? null;
            }
            fputcsv($fh, $line);
        }
        fclose($fh);

        return ['csv' => $csvPath, 'rows' => count($rows)];
    }
}
if (!function_exists('securityLevelFromScore')) {
    function securityLevelFromScore(int $score): string
    {
        if ($score <= 50) {
            return tr('Beginner', 'Fillestar');
        }
        if ($score <= 150) {
            return tr('Aware User', 'Perdorues i Vetedijshem');
        }
        if ($score <= 300) {
            return tr('Security Savvy', 'I Zoti ne Siguri');
        }
        return tr('Phishing Hunter', 'Gjuetar i Phishing');
    }
}

if (!function_exists('syncUserSecurityScore')) {
    function syncUserSecurityScore(PDO $pdo, int $userId): int
    {
        if ($userId <= 0 || !tableHasColumn($pdo, 'users', 'security_score')) {
            return 0;
        }

        $stmt = $pdo->prepare(
            "SELECT
                SUM(CASE WHEN status = 'Safe' THEN 10 ELSE 0 END)
              + SUM(CASE WHEN status = 'Suspicious' THEN 3 ELSE 0 END)
              + SUM(CASE WHEN status = 'Dangerous' THEN 0 ELSE 0 END) AS total_points
             FROM scans
             WHERE user_id = :user_id"
        );
        $stmt->execute(['user_id' => $userId]);
        $score = (int) ($stmt->fetchColumn() ?: 0);

        $update = $pdo->prepare('UPDATE users SET security_score = :score WHERE id = :id');
        $update->execute([
            'score' => $score,
            'id' => $userId,
        ]);

        return $score;
    }
}
