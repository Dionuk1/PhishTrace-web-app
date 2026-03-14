<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

require_once dirname(__DIR__) . '/includes/db.php';
require_once __DIR__ . '/ScanBuffer.php';

$buffer = new ScanBuffer();
$pdo = getPDO();
$maxJobs = resolveMaxJobs($argv ?? []);
$processed = 0;

$insert = $pdo->prepare(
    'INSERT INTO scans (user_id, url, domain, risk_score, status, reasons)
     VALUES (:user_id, :url, :domain, :risk_score, :status, :reasons)'
);

while ($processed < $maxJobs) {
    $claimed = $buffer->claimNext();
    if ($claimed === null) {
        break;
    }

    $path = $claimed['path'];
    $job = $claimed['job'];

    try {
        $payload = validatePayload($job['payload'] ?? []);
        $insert->execute([
            'user_id' => $payload['user_id'],
            'url' => $payload['url'],
            'domain' => $payload['domain'] !== '' ? $payload['domain'] : null,
            'risk_score' => $payload['risk_score'],
            'status' => $payload['status'],
            'reasons' => $payload['reasons'] !== '' ? $payload['reasons'] : null,
        ]);

        $buffer->complete($path);
        $processed++;
        fwrite(STDOUT, sprintf(
            "[%s] processed job %s%s",
            date('Y-m-d H:i:s'),
            $job['job_id'] ?? basename($path, '.json'),
            PHP_EOL
        ));
    } catch (Throwable $exception) {
        $failedPath = $buffer->fail($path, $exception->getMessage());
        fwrite(STDERR, sprintf(
            "[%s] failed job %s: %s (%s)%s",
            date('Y-m-d H:i:s'),
            $job['job_id'] ?? basename($path, '.json'),
            $exception->getMessage(),
            $failedPath,
            PHP_EOL
        ));
    }
}

fwrite(STDOUT, sprintf(
    "[%s] drain complete, processed=%d%s",
    date('Y-m-d H:i:s'),
    $processed,
    PHP_EOL
));

function resolveMaxJobs(array $argv): int
{
    foreach ($argv as $arg) {
        if (str_starts_with($arg, '--max=')) {
            $value = (int) substr($arg, 6);
            return $value > 0 ? $value : 100;
        }
    }

    return 100;
}

function validatePayload(array $payload): array
{
    $userId = (int) ($payload['user_id'] ?? 0);
    $url = trim((string) ($payload['url'] ?? ''));
    $domain = trim((string) ($payload['domain'] ?? ''));
    $riskScore = (int) ($payload['risk_score'] ?? 0);
    $status = trim((string) ($payload['status'] ?? ''));
    $reasons = trim((string) ($payload['reasons'] ?? ''));

    if ($userId <= 0) {
        throw new InvalidArgumentException('Invalid user_id.');
    }

    if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
        throw new InvalidArgumentException('Invalid url.');
    }

    if (!in_array($status, ['Safe', 'Suspicious', 'Dangerous'], true)) {
        throw new InvalidArgumentException('Invalid status.');
    }

    if ($riskScore < 0) {
        throw new InvalidArgumentException('Invalid risk_score.');
    }

    return [
        'user_id' => $userId,
        'url' => $url,
        'domain' => $domain,
        'risk_score' => $riskScore,
        'status' => $status,
        'reasons' => $reasons,
    ];
}
