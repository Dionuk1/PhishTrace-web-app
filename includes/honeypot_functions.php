<?php
// Honeypot helpers for logging, scoring, and reporting.

declare(strict_types=1);

/**
 * Initialize honeypot logging table if it doesn't exist.
 * Auto-creates on first use with proper schema.
 */
function initHoneypotTable(PDO $pdo): void
{
    if (isTableUsable($pdo, 'honeypot_logs')) {
        return;
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS honeypot_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sender_info VARCHAR(255) NOT NULL,
            message_text LONGTEXT NOT NULL,
            extracted_url JSON,
            risk_score INT DEFAULT 0,
            detected_keywords JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_risk_score (risk_score),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    );
}

/**
 * Extract URLs from message text using regex.
 */
function extractUrlsFromText(string $text): array
{
    $urls = [];
    $pattern = '#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i';

    if (preg_match_all($pattern, $text, $matches)) {
        $urls = array_unique((array) ($matches[0] ?? []));
    }

    return array_values($urls);
}

/**
 * Detect malicious keywords in message text.
 * Returns array of found keywords.
 */
function detectHoneypotKeywords(string $text): array
{
    $keywords = [
        'win', 'prize', 'gift', 'free', 'claim',
        'verify', 'confirm', 'login', 'urgent',
        'click', 'act now', 'limited time', 'congratulations',
        'reset password', 'update account', 'confirm identity',
        'security alert', 'unusual activity', 'banned', 'suspended',
        'airdrop', 'bonus', 'reward', 'crypto', 'wallet',
        'connect wallet', 'approve', 'transaction',
    ];

    $lowerText = strtolower($text);
    $detected = [];

    foreach ($keywords as $keyword) {
        if (str_contains($lowerText, $keyword)) {
            $detected[] = $keyword;
        }
    }

    return array_values(array_unique($detected));
}

/**
 * Calculate risk score for honeypot message (0-100).
 * Based on keywords, URLs, and patterns.
 */
function calculateHoneypotRiskScore(string $messageText, array $detectedKeywords, array $extractedUrls): int
{
    $score = 0;

    // Base score from keyword count
    $score += count($detectedKeywords) * 10;

    // Bonus for specific high-risk keywords
    $highRiskKeywords = ['verify', 'confirm', 'urgent', 'click', 'act now', 'banned', 'suspended'];
    foreach ($highRiskKeywords as $keyword) {
        if (in_array($keyword, $detectedKeywords, true)) {
            $score += 8;
        }
    }

    // Score based on URL count
    $score += count($extractedUrls) * 5;

    // Check if message contains all caps (often phishing)
    if (strlen($messageText) > 10 && preg_match('/[A-Z]{5,}/', $messageText)) {
        $score += 5;
    }

    // Check for urgency indicators
    if (preg_match('/!(!!!|!!)/', $messageText)) {
        $score += 5;
    }

    return min(100, max(0, (int) $score));
}

/**
 * Log a honeypot message to database.
 */
function logHoneypotMessage(PDO $pdo, string $senderInfo, string $messageText): int
{
    initHoneypotTable($pdo);

    $keywords = detectHoneypotKeywords($messageText);
    $urls = extractUrlsFromText($messageText);
    $riskScore = calculateHoneypotRiskScore($messageText, $keywords, $urls);

    $stmt = $pdo->prepare(
        'INSERT INTO honeypot_logs (sender_info, message_text, extracted_url, risk_score, detected_keywords)
         VALUES (:sender_info, :message_text, :extracted_url, :risk_score, :detected_keywords)'
    );

    $stmt->execute([
        'sender_info' => $senderInfo,
        'message_text' => $messageText,
        'extracted_url' => json_encode($urls, JSON_UNESCAPED_SLASHES),
        'risk_score' => $riskScore,
        'detected_keywords' => json_encode($keywords, JSON_UNESCAPED_SLASHES),
    ]);

    return (int) $pdo->lastInsertId();
}

/**
 * Get honeypot logs with pagination.
 */
function getHoneypotLogs(PDO $pdo, int $limit = 20, int $offset = 0): array
{
    initHoneypotTable($pdo);

    $stmt = $pdo->prepare(
        'SELECT id, sender_info, message_text, extracted_url, risk_score, detected_keywords, created_at
         FROM honeypot_logs
         ORDER BY created_at DESC
         LIMIT :limit OFFSET :offset'
    );

    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
}

/**
 * Get honeypot statistics.
 */
function getHoneypotStats(PDO $pdo): array
{
    initHoneypotTable($pdo);

    $totalStmt = $pdo->query('SELECT COUNT(*) FROM honeypot_logs');
    $totalMessages = (int) ($totalStmt->fetchColumn() ?: 0);

    $highRiskStmt = $pdo->query('SELECT COUNT(*) FROM honeypot_logs WHERE risk_score >= 80');
    $highRiskCount = (int) ($highRiskStmt->fetchColumn() ?: 0);

    $ipsStmt = $pdo->query('SELECT COUNT(DISTINCT sender_info) FROM honeypot_logs');
    $uniqueIPs = (int) ($ipsStmt->fetchColumn() ?: 0);

    $urlsStmt = $pdo->query(
        'SELECT COUNT(DISTINCT JSON_UNQUOTE(JSON_EXTRACT(extracted_url, "$[0]"))) 
         FROM honeypot_logs WHERE extracted_url IS NOT NULL AND JSON_LENGTH(extracted_url) > 0'
    );
    $uniqueUrls = (int) ($urlsStmt->fetchColumn() ?: 0);

    return [
        'total_messages' => $totalMessages,
        'high_risk_count' => $highRiskCount,
        'unique_ips' => $uniqueIPs,
        'unique_urls' => $uniqueUrls,
    ];
}

/**
 * Delete honeypot log entry.
 */
function deleteHoneypotLog(PDO $pdo, int $logId): void
{
    if ($logId <= 0) {
        return;
    }

    $stmt = $pdo->prepare('DELETE FROM honeypot_logs WHERE id = :id');
    $stmt->execute(['id' => $logId]);
}

/**
 * Get top detected keywords from honeypot logs.
 */
function getTopHoneypotKeywords(PDO $pdo, int $limit = 10): array
{
    initHoneypotTable($pdo);

    $logs = $pdo->query(
        'SELECT detected_keywords FROM honeypot_logs 
         WHERE detected_keywords IS NOT NULL 
         ORDER BY created_at DESC'
    )->fetchAll(PDO::FETCH_ASSOC);

    $keywordCounts = [];
    foreach ($logs as $log) {
        $keywords = json_decode((string) ($log['detected_keywords'] ?? '[]'), true);
        if (is_array($keywords)) {
            foreach ($keywords as $kw) {
                $keywordCounts[$kw] = ($keywordCounts[$kw] ?? 0) + 1;
            }
        }
    }

    arsort($keywordCounts);
    $topKeywords = array_slice($keywordCounts, 0, $limit);

    $result = [];
    foreach ($topKeywords as $keyword => $count) {
        $result[] = ['keyword' => (string) $keyword, 'count' => (int) $count];
    }

    return $result;
}

/**
 * Get suspicious URLs extracted from honeypot messages.
 */
function getSuspiciousHoneypotUrls(PDO $pdo, int $limit = 10): array
{
    initHoneypotTable($pdo);

    $logs = $pdo->query(
        'SELECT extracted_url, created_at FROM honeypot_logs 
         WHERE extracted_url IS NOT NULL 
         ORDER BY created_at DESC'
    )->fetchAll(PDO::FETCH_ASSOC);

    $urlData = [];
    foreach ($logs as $log) {
        $urls = json_decode((string) ($log['extracted_url'] ?? '[]'), true);
        if (is_array($urls)) {
            foreach ($urls as $url) {
                if (!isset($urlData[$url])) {
                    $urlData[$url] = [
                        'url' => (string) $url,
                        'count' => 0,
                        'first_seen' => (string) ($log['created_at'] ?? ''),
                        'domain' => (string) (parse_url($url, PHP_URL_HOST) ?? 'unknown'),
                    ];
                }
                $urlData[$url]['count']++;
            }
        }
    }

    uasort($urlData, fn($a, $b) => $b['count'] <=> $a['count']);

    return array_slice($urlData, 0, $limit);
}
