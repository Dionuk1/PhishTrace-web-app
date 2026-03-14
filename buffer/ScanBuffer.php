<?php
declare(strict_types=1);

/**
 * PhishTrace file-backed scan buffer.
 *
 * This queue is intentionally filesystem-based so it can be introduced
 * without changing the existing database connection or scan flow.
 */
final class ScanBuffer
{
    private string $baseDir;
    private string $pendingDir;
    private string $processingDir;
    private string $failedDir;

    public function __construct(?string $baseDir = null)
    {
        $this->baseDir = $baseDir ?? __DIR__ . DIRECTORY_SEPARATOR . 'runtime';
        $this->pendingDir = $this->baseDir . DIRECTORY_SEPARATOR . 'pending';
        $this->processingDir = $this->baseDir . DIRECTORY_SEPARATOR . 'processing';
        $this->failedDir = $this->baseDir . DIRECTORY_SEPARATOR . 'failed';

        $this->ensureDirectory($this->pendingDir);
        $this->ensureDirectory($this->processingDir);
        $this->ensureDirectory($this->failedDir);
    }

    /**
     * Store a scan payload for later processing.
     */
    public function enqueue(array $payload): string
    {
        $jobId = $this->generateJobId();
        $jobPath = $this->pendingDir . DIRECTORY_SEPARATOR . $jobId . '.json';

        $job = [
            'job_id' => $jobId,
            'queued_at' => gmdate('c'),
            'attempts' => 0,
            'payload' => $this->normalizePayload($payload),
        ];

        $encoded = json_encode($job, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            throw new RuntimeException('Unable to encode buffer payload.');
        }

        if (file_put_contents($jobPath, $encoded . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('Unable to write scan buffer job.');
        }

        return $jobId;
    }

    /**
     * Atomically move the next pending job into processing.
     */
    public function claimNext(): ?array
    {
        $files = glob($this->pendingDir . DIRECTORY_SEPARATOR . '*.json');
        if ($files === false || $files === []) {
            return null;
        }

        sort($files, SORT_STRING);

        foreach ($files as $pendingPath) {
            $processingPath = $this->processingDir . DIRECTORY_SEPARATOR . basename($pendingPath);
            if (!@rename($pendingPath, $processingPath)) {
                continue;
            }

            $job = $this->readJobFile($processingPath);
            $job['attempts'] = isset($job['attempts']) ? ((int) $job['attempts']) + 1 : 1;
            $job['claimed_at'] = gmdate('c');
            $this->writeJobFile($processingPath, $job);

            return [
                'path' => $processingPath,
                'job' => $job,
            ];
        }

        return null;
    }

    /**
     * Remove a successfully processed job.
     */
    public function complete(string $processingPath): void
    {
        if (is_file($processingPath)) {
            @unlink($processingPath);
        }
    }

    /**
     * Preserve a failed job for inspection and retry analysis.
     */
    public function fail(string $processingPath, string $reason): string
    {
        $job = $this->readJobFile($processingPath);
        $job['failed_at'] = gmdate('c');
        $job['failure_reason'] = $reason;

        $failedPath = $this->failedDir . DIRECTORY_SEPARATOR . basename($processingPath);
        $this->writeJobFile($failedPath, $job);

        if (is_file($processingPath)) {
            @unlink($processingPath);
        }

        return $failedPath;
    }

    private function normalizePayload(array $payload): array
    {
        return [
            'user_id' => isset($payload['user_id']) ? (int) $payload['user_id'] : 0,
            'url' => trim((string) ($payload['url'] ?? '')),
            'domain' => trim((string) ($payload['domain'] ?? '')),
            'risk_score' => isset($payload['risk_score']) ? (int) $payload['risk_score'] : 0,
            'status' => trim((string) ($payload['status'] ?? 'Safe')),
            'reasons' => trim((string) ($payload['reasons'] ?? '')),
        ];
    }

    private function readJobFile(string $path): array
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException('Unable to read buffer job: ' . $path);
        }

        $job = json_decode($contents, true);
        if (!is_array($job)) {
            throw new RuntimeException('Invalid buffer job payload: ' . $path);
        }

        return $job;
    }

    private function writeJobFile(string $path, array $job): void
    {
        $encoded = json_encode($job, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            throw new RuntimeException('Unable to encode buffer job payload.');
        }

        if (file_put_contents($path, $encoded . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('Unable to write buffer job file.');
        }
    }

    private function ensureDirectory(string $path): void
    {
        if (is_dir($path)) {
            return;
        }

        if (!mkdir($path, 0775, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create buffer directory: ' . $path);
        }
    }

    private function generateJobId(): string
    {
        return gmdate('YmdHis') . '_' . bin2hex(random_bytes(8));
    }
}
