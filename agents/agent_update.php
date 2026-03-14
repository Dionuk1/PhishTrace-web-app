<?php
// Automatic threat intelligence updater for PhishTrace.
// This script is safe for scheduler execution every 30 minutes.

declare(strict_types=1);

require_once __DIR__ . '/../includes/db.php';

const SS_AGENT_NAME = 'OpenPhishAgentUpdate';
const SS_FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const SS_MAX_URLS_PER_RUN = 2000;

function ssExtractDomainFromUrl(string $url): string
{
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

function ssLogAgentRun(PDO $pdo, int $entriesImported, string $status): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO agent_logs (agent_name, entries_imported, status) VALUES (:agent_name, :entries_imported, :status)'
    );
    $stmt->execute([
        'agent_name' => SS_AGENT_NAME,
        'entries_imported' => $entriesImported,
        'status' => $status,
    ]);
}

/**
 * Run one OpenPhish update cycle.
 *
 * @return array{status:string, entries_imported:int, message:string}
 */
function runOpenPhishAgentUpdate(?PDO $existingPdo = null): array
{
    $pdo = $existingPdo ?? getPDO();

    try {
        $feedRaw = @file_get_contents(SS_FEED_URL);
        if ($feedRaw === false) {
            throw new RuntimeException('Could not download OpenPhish feed.');
        }

        $lines = preg_split('/\r\n|\r|\n/', trim($feedRaw)) ?: [];
        $inserted = 0;
        $processed = 0;

        $stmt = $pdo->prepare(
            'INSERT IGNORE INTO threat_feed (url, domain, source) VALUES (:url, :domain, :source)'
        );

        foreach ($lines as $line) {
            if ($processed >= SS_MAX_URLS_PER_RUN) {
                break;
            }

            $url = trim($line);
            if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
                continue;
            }

            $domain = ssExtractDomainFromUrl($url);
            if ($domain === '') {
                continue;
            }

            $stmt->execute([
                'url' => $url,
                'domain' => $domain,
                'source' => 'OpenPhish',
            ]);
            $processed++;

            if ($stmt->rowCount() > 0) {
                $inserted++;
            }
        }

        ssLogAgentRun($pdo, $inserted, 'success');

        return [
            'status' => 'success',
            'entries_imported' => $inserted,
            'message' => 'OpenPhish update completed successfully.',
        ];
    } catch (Throwable $exception) {
        ssLogAgentRun($pdo, 0, 'failed');

        return [
            'status' => 'failed',
            'entries_imported' => 0,
            'message' => $exception->getMessage(),
        ];
    }
}

// CLI/web direct execution support.
if (basename((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === basename(__FILE__)) {
    $result = runOpenPhishAgentUpdate();
    $line = sprintf(
        '%s | Imported: %d | %s',
        strtoupper($result['status']),
        (int) $result['entries_imported'],
        $result['message']
    );

    if (PHP_SAPI === 'cli') {
        echo $line . PHP_EOL;
    } else {
        header('Content-Type: text/plain; charset=UTF-8');
        echo $line;
    }
}
