<?php
// Shared utility + phishing analysis logic.

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

function appBaseUrl(): string
{
    static $base = null;

    if ($base !== null) {
        return $base;
    }

    $scriptName = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? ''));
    $base = (string) dirname($scriptName);

    if (str_contains($scriptName, '/admin/')) {
        $base = (string) preg_replace('#/admin/.*$#', '', $scriptName);
    }

    if ($base === '.' || $base === '/') {
        $base = '';
    }

    return rtrim($base, '/');
}

function appPath(string $path = ''): string
{
    $cleanPath = ltrim($path, '/');
    $base = appBaseUrl();
    return $base . ($cleanPath !== '' ? '/' . $cleanPath : '');
}

function isCurrentPage(string $path): bool
{
    $current = str_replace('\\', '/', (string) ($_SERVER['PHP_SELF'] ?? ''));
    return str_ends_with($current, '/' . ltrim($path, '/'));
}

function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function redirect(string $path): void
{
    header('Location: ' . appPath($path));
    exit;
}

function setFlash(string $message, string $type = 'info'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function getFlash(): ?array
{
    if (!isset($_SESSION['flash'])) {
        return null;
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $flash;
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || $token === null) {
        return false;
    }

    return hash_equals($_SESSION['csrf_token'], $token);
}

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

function statusBadgeClass(string $status): string
{
    return match ($status) {
        'Safe' => 'success',
        'Suspicious' => 'warning',
        'Dangerous' => 'danger',
        default => 'secondary',
    };
}

function scoreToConfidence(int $score): int
{
    return max(0, min(100, $score));
}

function securityLevelFromScore(int $securityScore): string
{
    if ($securityScore <= 50) {
        return 'Beginner';
    }
    if ($securityScore <= 150) {
        return 'Aware User';
    }
    if ($securityScore <= 300) {
        return 'Security Savvy';
    }
    return 'Phishing Hunter';
}

function securityPointsByStatus(string $status): int
{
    return match ($status) {
        'Safe' => 10,
        'Suspicious' => 3,
        'Dangerous' => 1,
        default => 0,
    };
}

function scoreToThreatLevel(int $score): string
{
    if ($score <= 20) {
        return 'LOW';
    }
    if ($score <= 50) {
        return 'MEDIUM';
    }
    return 'HIGH';
}

function isSuspiciousTld(string $host): bool
{
    $tld = strtolower(pathinfo($host, PATHINFO_EXTENSION));
    $suspiciousTlds = ['xyz', 'top', 'click', 'gq', 'ml', 'tk', 'cf'];
    return in_array($tld, $suspiciousTlds, true);
}

function detectBrandImpersonation(string $host): ?string
{
    $brands = ['facebook', 'instagram', 'paypal', 'binance', 'twitter', 'discord'];
    $labels = explode('.', $host);

    // Common lookalike patterns seen in phishing domains.
    $knownImpersonations = [
        'faceb00k' => 'facebook',
        'instagrarn' => 'instagram',
        'paypai' => 'paypal',   // lowercase for paypaI-like tricks
        'paypa1' => 'paypal',
    ];

    foreach ($labels as $label) {
        $label = strtolower($label);
        if ($label === '') {
            continue;
        }

        // Break compound labels: instagrarn-verification -> [instagrarn, verification]
        $parts = preg_split('/[^a-z0-9]+/', $label) ?: [];
        if ($parts === []) {
            $parts = [$label];
        }

        // Also test full label for contains patterns.
        $parts[] = $label;

        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            // Normalize common phishing substitutions before similarity check.
            $normalizedPart = strtr($part, [
                '0' => 'o',
                '1' => 'l',
                '3' => 'e',
                '4' => 'a',
                '5' => 's',
                '7' => 't',
            ]);

            if (isset($knownImpersonations[$part])) {
                return $knownImpersonations[$part];
            }

            foreach ($knownImpersonations as $fake => $real) {
                if (str_contains($part, $fake)) {
                    return $real;
                }
            }

            foreach ($brands as $brand) {
                // Brand not exact, but close enough to likely impersonation.
                $distance = levenshtein($part, $brand);
                $normalizedDistance = levenshtein($normalizedPart, $brand);

                if (($part !== $brand && $distance > 0 && $distance <= 2)
                    || ($normalizedPart !== $brand && $normalizedDistance > 0 && $normalizedDistance <= 2)) {
                    return $brand;
                }
            }
        }
    }

    return null;
}

function parseReasons(string $json): array
{
    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : [];
}

function tableHasColumn(PDO $pdo, string $tableName, string $columnName): bool
{
    static $cache = [];
    $key = $tableName . ':' . $columnName;
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name'
    );
    $stmt->execute([
        'table_name' => $tableName,
        'column_name' => $columnName,
    ]);

    $cache[$key] = ((int) $stmt->fetchColumn()) > 0;
    return $cache[$key];
}

function isDomainInThreatFeed(PDO $pdo, string $host): bool
{
    if ($host === '') {
        return false;
    }

    $stmt = $pdo->prepare(
        "SELECT 1
         FROM threat_feed
         WHERE domain = :host_exact OR :host_sub LIKE CONCAT('%.', domain)
         LIMIT 1"
    );
    $stmt->execute([
        'host_exact' => $host,
        'host_sub' => $host,
    ]);

    return (bool) $stmt->fetchColumn();
}

function analyzeUrl(string $inputUrl, PDO $pdo): array
{
    $url = trim((string) filter_var($inputUrl, FILTER_SANITIZE_URL));
    $riskScore = 0;
    $reasons = [];
    $details = [];
    $indicators = [];

    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return [
            'valid' => false,
            'url' => $url,
            'domain' => '',
            'risk_score' => 0,
            'confidence' => 0,
            'status' => 'Suspicious',
            'reasons' => ['Invalid URL format. Include http:// or https://'],
            'details' => ['URL validation failed.'],
            'indicators' => [],
        ];
    }

    $parts = parse_url($url);
    $host = normalizeDomain((string) ($parts['host'] ?? ''));
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $path = strtolower((string) ($parts['path'] ?? ''));
    $pathAndQuery = strtolower((string) (($parts['path'] ?? '') . '?' . ($parts['query'] ?? '')));
    $fullLower = strtolower($url);
    $queryString = (string) ($parts['query'] ?? '');
    $forceDangerous = false;

    // Threat feed check must happen before the normal risk scoring rules.
    if (isDomainInThreatFeed($pdo, $host)) {
        $riskScore += 80;
        $forceDangerous = true;
        $reasons[] = 'Domain found in OpenPhish threat feed (+80)';
        $details[] = 'Threat feed match indicates this domain has known phishing activity.';
        $indicators[] = ['rule' => 'Threat Feed Match', 'points' => 80, 'evidence' => $host, 'explanation' => 'OpenPhish feed contains this domain.'];
    }

    // 1) HTTPS check
    if ($scheme !== 'https') {
        $riskScore += 20;
        $reasons[] = 'URL does not use HTTPS (+20)';
        $details[] = 'Without HTTPS, traffic can be intercepted more easily.';
        $indicators[] = ['rule' => 'No HTTPS', 'points' => 20, 'evidence' => strtoupper($scheme ?: 'NONE'), 'explanation' => 'Secure sites should use HTTPS.'];
    }

    // 2) URL Length Detection
    if (strlen($url) > 75) {
        $riskScore += 10;
        $reasons[] = 'URL length unusually long (+10)';
        $details[] = 'Long URLs can hide malicious paths and redirects.';
        $indicators[] = ['rule' => 'Long URL', 'points' => 10, 'evidence' => strlen($url) . ' characters', 'explanation' => 'Excessively long links are often suspicious.'];
    }

    // 3) Suspicious Keyword Highlight
    $keywords = ['login', 'verify', 'reset', 'secure', 'wallet', 'claim', 'bonus', 'update', 'account'];
    $foundKeywords = [];
    foreach ($keywords as $keyword) {
        if (str_contains($fullLower, $keyword)) {
            $foundKeywords[] = $keyword;
        }
    }
    if ($foundKeywords !== []) {
        $riskScore += 15;
        $keywordText = implode(', ', array_unique($foundKeywords));
        $reasons[] = 'Suspicious keyword(s) detected: ' . $keywordText . ' (+15)';
        $details[] = 'Phishing URLs often use urgent words to pressure users.';
        $indicators[] = ['rule' => 'Suspicious Keywords', 'points' => 15, 'evidence' => $keywordText, 'explanation' => 'Urgent/account words are common in phishing.'];
    }

    // Fake Login Page Detection (path-based).
    $loginPathWords = ['login', 'signin', 'verify', 'authentication', 'reset-password', 'account-check', 'security-check'];
    $matchedPathWords = [];
    foreach ($loginPathWords as $word) {
        if ($path !== '' && str_contains($path, $word)) {
            $matchedPathWords[] = $word;
        }
    }
    if ($matchedPathWords !== []) {
        $riskScore += 15;
        $reasons[] = 'URL contains login-related path commonly used in phishing pages (+15)';
        $details[] = 'Matched path keywords: ' . implode(', ', array_unique($matchedPathWords));
        $indicators[] = ['rule' => 'Fake Login Path', 'points' => 15, 'evidence' => implode(', ', array_unique($matchedPathWords)), 'explanation' => 'Phishing pages often use login/verify/reset style paths to impersonate account portals.'];
    }

    // Nested paths detection: /a/b/c/d/e (more than 4 segments).
    $pathSegments = array_values(array_filter(explode('/', trim($path, '/'))));
    if (count($pathSegments) > 4) {
        $riskScore += 10;
        $reasons[] = 'URL contains many nested paths (+10)';
        $details[] = 'Deeply nested paths can be used to obfuscate phishing destinations.';
        $indicators[] = ['rule' => 'Nested Paths', 'points' => 10, 'evidence' => count($pathSegments) . ' path segments', 'explanation' => 'Excessive path depth can be a phishing URL pattern.'];
    }

    // 4) Excessive hyphens in domain
    if (substr_count($host, '-') > 3) {
        $riskScore += 10;
        $reasons[] = 'Domain contains excessive hyphens (+10)';
        $details[] = 'Fake domains often overuse hyphens.';
        $indicators[] = ['rule' => 'Excessive Hyphens', 'points' => 10, 'evidence' => (string) substr_count($host, '-') . ' hyphens', 'explanation' => 'Hyphen-heavy domains can indicate generated scam domains.'];
    }

    // Long domain names.
    if (strlen($host) > 30) {
        $riskScore += 10;
        $reasons[] = 'Domain name unusually long (+10)';
        $details[] = 'Unusually long domains may be generated to mimic trusted services.';
        $indicators[] = ['rule' => 'Long Domain Name', 'points' => 10, 'evidence' => strlen($host) . ' characters', 'explanation' => 'Very long domains can hide brand impersonation patterns.'];
    }

    // 5) Subdomain Abuse Detection
    $labels = array_values(array_filter(explode('.', $host)));
    $subdomainCount = max(0, count($labels) - 2);
    if ($subdomainCount > 3) {
        $riskScore += 15;
        $reasons[] = 'Multiple subdomains detected (+15)';
        $details[] = 'Complex subdomain structures can hide deceptive hosts.';
        $indicators[] = ['rule' => 'Subdomain Abuse', 'points' => 15, 'evidence' => $subdomainCount . ' subdomains', 'explanation' => 'Deep subdomains can mislead users.'];
    }

    // 6) @ Symbol Detection
    if (str_contains($url, '@')) {
        $riskScore += 20;
        $reasons[] = 'URL contains @ symbol which may hide the real domain (+20)';
        $details[] = '@ can hide the true destination in crafted URLs.';
        $indicators[] = ['rule' => '@ Symbol', 'points' => 20, 'evidence' => '@ found in URL', 'explanation' => 'The @ character is frequently abused in phishing links.'];
    }

    // 7) Suspicious Character Detection
    $specialCharCount = preg_match_all('/[_%=&]/', $url);
    if ($specialCharCount !== false && $specialCharCount > 4) {
        $riskScore += 10;
        $reasons[] = 'URL contains suspicious characters (+10)';
        $details[] = 'Many special characters can indicate obfuscation attempts.';
        $indicators[] = ['rule' => 'Suspicious Characters', 'points' => 10, 'evidence' => $specialCharCount . ' special chars (_ % = &)', 'explanation' => 'Attackers may use special characters to hide real intent.'];
    }

    // 8) Suspicious IP Address URL
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $riskScore += 25;
        $reasons[] = 'URL uses IP address instead of domain (+25)';
        $details[] = 'Trusted social platforms usually use official domain names.';
        $indicators[] = ['rule' => 'IP Address', 'points' => 25, 'evidence' => $host, 'explanation' => 'IP-hosted links are higher risk in social scams.'];
    }

    // 8) Blacklist lookup
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
        $row = $stmt->fetch();

        if ($row) {
            $riskScore += 50;
            $reasons[] = 'Domain is blacklisted (+50)';
            $details[] = 'Blacklist reason: ' . ($row['reason'] ?: 'Known malicious domain');
            $indicators[] = ['rule' => 'Blacklisted Domain', 'points' => 50, 'evidence' => (string) $row['domain'], 'explanation' => 'This domain exists in your threat list.'];
        }
    }

    // 9) Brand Impersonation Detection
    $brand = detectBrandImpersonation($host);
    if ($brand !== null) {
        $riskScore += 30;
        $reasons[] = 'Possible brand impersonation detected (+30)';
        $details[] = 'The domain appears to mimic a known brand.';
        $indicators[] = ['rule' => 'Brand Impersonation', 'points' => 30, 'evidence' => 'Mimicked brand: ' . $brand, 'explanation' => 'Typos and lookalike brand names are common phishing tactics.'];
    }

    // 10) Suspicious TLD Detection
    if (isSuspiciousTld($host)) {
        $riskScore += 15;
        $reasons[] = 'Suspicious top-level domain detected (+15)';
        $details[] = 'Some TLDs are more frequently used in scams.';
        $indicators[] = ['rule' => 'Suspicious TLD', 'points' => 15, 'evidence' => pathinfo($host, PATHINFO_EXTENSION), 'explanation' => 'This TLD appears often in phishing campaigns.'];
    }

    // 10) Too Many Query Parameters
    parse_str($queryString, $queryArray);
    if (count($queryArray) > 4) {
        $riskScore += 10;
        $reasons[] = 'URL contains many query parameters (+10)';
        $details[] = 'Large query strings can be used for obfuscation or tracking.';
        $indicators[] = ['rule' => 'Many Query Parameters', 'points' => 10, 'evidence' => count($queryArray) . ' parameters', 'explanation' => 'Overloaded URLs can hide intent.'];
    }

    // 12) Encoded/obfuscated patterns
    if (preg_match('/%[0-9a-f]{2}/i', $url) || str_contains($pathAndQuery, 'base64') || str_contains($pathAndQuery, '%2f') || str_contains($pathAndQuery, '%3a')) {
        $riskScore += 15;
        $reasons[] = 'Encoded or obfuscated URL patterns detected (+15)';
        $details[] = 'Encoded characters may hide malicious redirects or payloads.';
        $indicators[] = ['rule' => 'Obfuscation Pattern', 'points' => 15, 'evidence' => 'Encoded sequence or obfuscation keyword found', 'explanation' => 'Attackers obfuscate URLs to avoid quick detection.'];
    }

    if ($reasons === []) {
        $reasons[] = 'No suspicious indicators triggered.';
        $details[] = 'The URL looks safe under current rule-based checks.';
    }

    return [
        'valid' => true,
        'url' => $url,
        'domain' => $host,
        'risk_score' => $riskScore,
        'confidence' => scoreToConfidence($riskScore),
        'threat_level' => scoreToThreatLevel($riskScore),
        'status' => $forceDangerous ? 'Dangerous' : scoreToStatus($riskScore),
        'reasons' => $reasons,
        'details' => $details,
        'indicators' => $indicators,
    ];
}

function saveScan(int $userId, string $url, string $domain, int $score, string $status, array $reasons, PDO $pdo): void
{
    $payload = [
        'user_id' => $userId,
        'url' => $url,
        'risk_score' => $score,
        'status' => $status,
        'reasons' => json_encode($reasons, JSON_UNESCAPED_UNICODE),
    ];

    // Backward-compatible insert for old schema versions that do not have scans.domain.
    if (tableHasColumn($pdo, 'scans', 'domain')) {
        $stmt = $pdo->prepare(
            'INSERT INTO scans (user_id, url, domain, risk_score, status, reasons)
             VALUES (:user_id, :url, :domain, :risk_score, :status, :reasons)'
        );
        $payload['domain'] = $domain;
    } else {
        $stmt = $pdo->prepare(
            'INSERT INTO scans (user_id, url, risk_score, status, reasons)
             VALUES (:user_id, :url, :risk_score, :status, :reasons)'
        );
    }

    $stmt->execute($payload);

    // Update Cyber Awareness score only if the schema has security_score.
    if (tableHasColumn($pdo, 'users', 'security_score')) {
        $points = securityPointsByStatus($status);
        if ($points > 0) {
            $scoreStmt = $pdo->prepare('UPDATE users SET security_score = COALESCE(security_score, 0) + :points WHERE id = :id');
            $scoreStmt->execute([
                'points' => $points,
                'id' => $userId,
            ]);
        }
    }
}

function socialSafetyRecommendations(): array
{
    return [
        'Enable 2FA on all social media accounts.',
        'Never trust urgent links sent by unknown accounts or DMs.',
        'Do not share personal information publicly (phone, location, IDs).',
        'Review connected app permissions regularly.',
        'Use strong, unique passwords for each account.',
        'Verify account alerts directly from official websites, not message links.',
        'Be careful with fake giveaways, bonus claims, and reward messages.',
    ];
}
