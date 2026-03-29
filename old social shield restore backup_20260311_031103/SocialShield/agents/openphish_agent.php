<?php
// OpenPhish threat intelligence import agent for SocialShield.

declare(strict_types=1);

require_once __DIR__ . '/../includes/db.php';

const AGENT_NAME = 'OpenPhishAgent';
const FEED_URL = 'https://openphish.com/feed.txt';

function normalizeFeedDomain(string $url): string
{
    $url = trim($url);
    if ($url === '') {
        return '';
    }

    $parts = parse_url($url);
    $host = strtolower(trim((string) ($parts['host'] ?? '')));
    if ($host === '') {
        return '';
    }

    if (str_starts_with($host, 'www.')) {
        $host = substr($host, 4);
    }

    return rtrim($host, '.');
}

function logAgentRun(PDO $pdo, int $entriesImported, string $status): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO agent_logs (agent_name, entries_imported, status) VALUES (:agent_name, :entries_imported, :status)'
    );
    $stmt->execute([
        'agent_name' => AGENT_NAME,
        'entries_imported' => $entriesImported,
        'status' => $status,
    ]);
}

try {
    $pdo = getPDO();

    $feedData = @file_get_contents(FEED_URL);
    if ($feedData === false) {
        throw new RuntimeException('Unable to download OpenPhish feed.');
    }

    $lines = preg_split('/\r\n|\r|\n/', trim($feedData)) ?: [];
    $inserted = 0;

    $stmt = $pdo->prepare(
        'INSERT IGNORE INTO threat_feed (url, domain, source) VALUES (:url, :domain, :source)'
    );

    foreach ($lines as $line) {
        $url = trim($line);
        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            continue;
        }

        $domain = normalizeFeedDomain($url);
        if ($domain === '') {
            continue;
        }

        $stmt->execute([
            'url' => $url,
            'domain' => $domain,
            'source' => 'OpenPhish',
        ]);

        if ($stmt->rowCount() > 0) {
            $inserted++;
        }
    }

    logAgentRun($pdo, $inserted, 'success');
    echo "OpenPhish agent completed. Imported: {$inserted}" . PHP_EOL;
} catch (Throwable $exception) {
    if (!isset($pdo) || !$pdo instanceof PDO) {
        $pdo = getPDO();
    }
    logAgentRun($pdo, 0, 'failed');
    echo 'OpenPhish agent failed: ' . $exception->getMessage() . PHP_EOL;
    exit(1);
}
