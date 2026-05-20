<?php
/**
 * JSON logger for analyzed honeypot results.
 *
 * Each log entry contains:
 * - id
 * - username
 * - message
 * - detected_keywords
 * - urls
 * - risk_score
 * - risk_level
 * - timestamp
 */

declare(strict_types=1);

class HoneypotAnalysisLogger
{
    private string $logDir;
    private string $logFile;

    public function __construct(string $logDir)
    {
        $this->logDir = $logDir;
        $this->logFile = $logDir . '/honeypot_analysis_logs.json';

        if (!is_dir($this->logDir)) {
            mkdir($this->logDir, 0755, true);
        }

        if (!file_exists($this->logFile)) {
            file_put_contents($this->logFile, json_encode([], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
    }

    /**
     * Append a log entry to the JSON log file.
     *
     * @param array{
     *   id:int,
     *   username:string,
     *   message:string,
     *   detected_keywords:string[],
     *   urls:string[],
     *   risk_score:int,
     *   risk_level:string,
     *   timestamp:string
     * } $entry
     */
    public function log(array $entry): bool
    {
        $logs = $this->getAllLogs();
        $logs[] = [
            'id' => (int) ($entry['id'] ?? 0),
            'username' => (string) ($entry['username'] ?? ''),
            'message' => (string) ($entry['message'] ?? ''),
            'detected_keywords' => array_values(array_unique($entry['detected_keywords'] ?? [])),
            'urls' => array_values(array_unique($entry['urls'] ?? [])),
            'risk_score' => (int) ($entry['risk_score'] ?? 0),
            'risk_level' => (string) ($entry['risk_level'] ?? 'Low'),
            'timestamp' => (string) ($entry['timestamp'] ?? date('Y-m-d H:i:s'))
        ];

        $jsonContent = json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($jsonContent === false) {
            return false;
        }

        return file_put_contents($this->logFile, $jsonContent) !== false;
    }

    /**
     * Read all log entries.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getAllLogs(): array
    {
        if (!file_exists($this->logFile)) {
            return [];
        }

        $content = file_get_contents($this->logFile);
        if ($content === false) {
            return [];
        }

        $logs = json_decode($content, true);
        return is_array($logs) ? $logs : [];
    }

    /**
     * Get log file path.
     */
    public function getLogFilePath(): string
    {
        return $this->logFile;
    }
}
