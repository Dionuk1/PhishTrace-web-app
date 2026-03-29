<?php
// General helper functions and URL risk analysis engine.

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

/**
 * Build base URL like "/phishtrace" regardless of current script depth.
 */
function appBaseUrl(): string
{
    static $base = null;

    if ($base !== null) {
        return $base;
    }

    $scriptName = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? ''));
    if (str_contains($scriptName, '/admin/')) {
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
 * Build absolute in-app URL path.
 */
function appPath(string $path = ''): string
{
    $cleanPath = ltrim($path, '/');
    $base = appBaseUrl();
    return $base . ($cleanPath !== '' ? '/' . $cleanPath : '');
}

/**
 * Basic output escaping for HTML.
 */
function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

/**
 * Redirect and stop script execution.
 */
function redirect(string $path): void
{
    header('Location: ' . appPath($path));
    exit;
}

/**
 * Flash message setter.
 */
function setFlash(string $message, string $type = 'info'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

/**
 * Flash message getter (one-time).
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
 * Generate and return CSRF token for forms.
 */
function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token from POST request.
 */
function verifyCsrfToken(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }

    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Clean URL input from the user.
 */
function sanitizeUrlInput(string $url): string
{
    return trim(filter_var($url, FILTER_SANITIZE_URL));
}

/**
 * Normalize domain for list comparisons.
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
 * Map score to the project thresholds.
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
 * Return badge class for result status.
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
 * User-facing label for risk state.
 */
function statusDisplayLabel(string $status): string
{
    return match ($status) {
        'Dangerous' => 'High Risk',
        default => $status,
    };
}

/**
 * Return environment variable from common sources.
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
 * Fetch remote HTML for live content inspection.
 */
function fetchRemoteHtml(string $url): array
{
    $userAgent = 'SocialShield-AI-Security-Assistant/1.0';
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
        curl_close($ch);

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

/**
 * Build prompt payload for AI explanation.
 */
function buildAiSecurityPrompt(array $analysis): string
{
    $indicatorLines = [];
    foreach (buildThreatIndicators($analysis) as $indicator) {
        $indicatorLines[] = $indicator['label'] . ': ' . $indicator['value'];
    }

    return implode("\n", [
        'Analyze this website security scan and write a short professional report.',
        'URL: ' . $analysis['url'],
        'Domain: ' . $analysis['domain'],
        'Risk score: ' . $analysis['risk_score'] . '/100',
        'Risk level: ' . statusDisplayLabel($analysis['status']),
        'Fetch status: ' . ($analysis['fetch']['ok'] ? 'HTML fetched successfully' : 'HTML fetch failed'),
        'Detected reasons: ' . implode('; ', $analysis['reasons']),
        'Threat indicators:',
        implode("\n", $indicatorLines),
        'Required format:',
        'AI Security Assistant Report',
        'Risk Level: <Safe/Suspicious/High>',
        'Reasons:',
        '- bullet list',
        'Recommendations:',
        '- bullet list',
    ]);
}

/**
 * Extract text from OpenAI Responses API payload.
 */
function extractOpenAiText(array $response): string
{
    if (!empty($response['output_text']) && is_string($response['output_text'])) {
        return trim($response['output_text']);
    }

    if (!empty($response['output']) && is_array($response['output'])) {
        $chunks = [];
        foreach ($response['output'] as $item) {
            if (empty($item['content']) || !is_array($item['content'])) {
                continue;
            }

            foreach ($item['content'] as $content) {
                if (($content['type'] ?? '') === 'output_text' && !empty($content['text'])) {
                    $chunks[] = trim((string) $content['text']);
                }
            }
        }

        return trim(implode("\n", array_filter($chunks)));
    }

    return '';
}

/**
 * Fallback explanation when OpenAI is unavailable.
 */
function buildFallbackAiReport(array $analysis): string
{
    $reasons = [];
    foreach ($analysis['reasons'] as $reason) {
        $reasons[] = '- ' . preg_replace('/\s*\(\+\d+\)$/', '', $reason);
    }

    $recommendations = [
        '- Do not enter credentials on the scanned page until the domain is independently verified.',
        '- Do not connect crypto wallets or approve browser wallet prompts on untrusted sites.',
        '- Confirm the brand domain manually and navigate to it directly instead of using the scanned link.',
    ];

    if ($analysis['html_analysis']['brand_mentions'] === [] && $analysis['html_analysis']['wallet_prompts'] === []) {
        $recommendations[] = '- Continue checking for cloned login pages, unexpected downloads, or unusual payment requests.';
    }

    return implode("\n", [
        'AI Security Assistant Report',
        '',
        'Risk Level: ' . statusDisplayLabel($analysis['status']),
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
 * Generate AI explanation using OpenAI with graceful fallback.
 */
function generateAiSecurityAssistantReport(array $analysis): array
{
    $apiKey = envValue('OPENAI_API_KEY');
    $model = envValue('OPENAI_MODEL', 'gpt-4.1-mini');

    if ($apiKey === null) {
        return [
            'text' => buildFallbackAiReport($analysis),
            'source' => 'fallback',
            'error' => 'OPENAI_API_KEY is not configured.',
        ];
    }

    if (!function_exists('curl_init')) {
        return [
            'text' => buildFallbackAiReport($analysis),
            'source' => 'fallback',
            'error' => 'cURL is not available for OpenAI API requests.',
        ];
    }

    $payload = [
        'model' => $model,
        'instructions' => 'You are SocialShield AI Security Assistant. Explain phishing risk clearly, reference only provided indicators, and give concise safety recommendations.',
        'input' => [
            [
                'role' => 'user',
                'content' => [
                    [
                        'type' => 'input_text',
                        'text' => buildAiSecurityPrompt($analysis),
                    ],
                ],
            ],
        ],
        'max_output_tokens' => 350,
    ];

    $ch = curl_init('https://api.openai.com/v1/responses');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $apiKey,
            'Content-Type: application/json',
        ],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    ]);

    $rawResponse = curl_exec($ch);
    $curlError = curl_error($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if (!is_string($rawResponse) || $rawResponse === '') {
        return [
            'text' => buildFallbackAiReport($analysis),
            'source' => 'fallback',
            'error' => $curlError !== '' ? $curlError : 'OpenAI API returned an empty response.',
        ];
    }

    $decoded = json_decode($rawResponse, true);
    $text = is_array($decoded) ? extractOpenAiText($decoded) : '';

    if ($statusCode >= 400 || $text === '') {
        return [
            'text' => buildFallbackAiReport($analysis),
            'source' => 'fallback',
            'error' => is_array($decoded) && isset($decoded['error']['message'])
                ? (string) $decoded['error']['message']
                : 'OpenAI API request failed.',
        ];
    }

    return [
        'text' => $text,
        'source' => 'openai',
        'error' => null,
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

    $summaryStmt = $pdo->prepare(
        'SELECT COUNT(*) AS total_achievements, COALESCE(SUM(a.points), 0) AS total_points
         FROM user_achievements ua
         INNER JOIN achievements a ON a.id = ua.achievement_id
         WHERE ua.user_id = :user_id'
    );
    $summaryStmt->execute(['user_id' => $userId]);
    $summary = $summaryStmt->fetch() ?: [];

    $latestStmt = $pdo->prepare(
        'SELECT a.title, a.description, a.points, ua.unlocked_at
         FROM user_achievements ua
         INNER JOIN achievements a ON a.id = ua.achievement_id
         WHERE ua.user_id = :user_id
         ORDER BY ua.unlocked_at DESC, ua.id DESC
         LIMIT 1'
    );
    $latestStmt->execute(['user_id' => $userId]);
    $latestUnlock = $latestStmt->fetch() ?: null;

    $listStmt = $pdo->prepare(
        'SELECT a.title, a.description, a.points, ua.unlocked_at
         FROM user_achievements ua
         INNER JOIN achievements a ON a.id = ua.achievement_id
         WHERE ua.user_id = :user_id
         ORDER BY ua.unlocked_at DESC, ua.id DESC'
    );
    $listStmt->execute(['user_id' => $userId]);

    return [
        'latest_unlock' => $latestUnlock,
        'total_achievements' => (int) ($summary['total_achievements'] ?? 0),
        'total_points' => (int) ($summary['total_points'] ?? 0),
        'achievements' => $listStmt->fetchAll() ?: [],
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
 */
function saveScan(int $userId, string $url, string $domain, int $riskScore, string $status, array $reasons, PDO $pdo): int
{
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
    $scanId = (int) $pdo->lastInsertId();

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
    
    return $scanId;
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

if (!function_exists('tr')) {
    function tr(string $en, string $sq): string
    {
        return currentLanguage() === 'sq' ? $sq : $en;
    }
}

if (!function_exists('t')) {
    function t(string $key): string
    {
        static $dict = [
            'en' => [
                'invalid_csrf' => 'Invalid CSRF token.',
                'language_saved' => 'Language saved.',
                'settings' => 'Settings',
                'language_settings' => 'Language Settings',
                'choose_language' => 'Choose your preferred language.',
                'english' => 'English',
                'albanian' => 'Albanian',
            ],
            'sq' => [
                'invalid_csrf' => 'Token CSRF i pavlefshem.',
                'language_saved' => 'Gjuha u ruajt.',
                'settings' => 'Cilesimet',
                'language_settings' => 'Cilesimet e Gjuhes',
                'choose_language' => 'Zgjidh gjuhen e preferuar.',
                'english' => 'Anglisht',
                'albanian' => 'Shqip',
            ],
        ];

        $lang = currentLanguage();
        $value = $dict[$lang][$key] ?? $dict['en'][$key] ?? null;
        if ($value !== null) {
            return $value;
        }

        return ucwords(str_replace('_', ' ', $key));
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
        // Store backups OUTSIDE web root in storage/backups
        // This assumes web root is /path/to/SocialShield and storage is /path/to/storage
        $webRoot = realpath(__DIR__ . '/..');
        $storageRoot = $webRoot . DIRECTORY_SEPARATOR . 'storage';
        $backupDir = $storageRoot . DIRECTORY_SEPARATOR . 'backups';
        
        // Create storage directory structure if it doesn't exist
        if (!is_dir($storageRoot)) {
            if (!mkdir($storageRoot, 0700, true) && !is_dir($storageRoot)) {
                throw new RuntimeException('Could not create storage directory.');
            }
            
            // Add .htaccess to deny web access
            file_put_contents(
                $storageRoot . DIRECTORY_SEPARATOR . '.htaccess',
                "# Security: Deny all web access to storage directory\n" .
                "Require all denied\n"
            );
        }
        
        // Create backups subdirectory
        if (!is_dir($backupDir) && !mkdir($backupDir, 0700, true) && !is_dir($backupDir)) {
            throw new RuntimeException('Could not create backups directory.');
        }
        
        return $backupDir;
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