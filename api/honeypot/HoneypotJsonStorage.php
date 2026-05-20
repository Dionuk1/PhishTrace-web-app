<?php
/**
 * Simple in-memory JSON storage helper for honeypot messages.
 * Alternative to database storage - stores messages in JSON file.
 */

declare(strict_types=1);

require_once __DIR__ . '/HoneypotRiskScorer.php';
require_once __DIR__ . '/HoneypotAnalysisLogger.php';
require_once __DIR__ . '/UrlPhishingDetector.php';

class HoneypotJsonStorage
{
    private string $dataDir;
    private string $storageFile;
    private array $suspiciousKeywords = [
        'verify', 'login', 'urgent', 'free', 'click', 'claim', 'reward', 'password', 'confirm'
    ];

    public function __construct(string $dataDir)
    {
        $this->dataDir = $dataDir;
        $this->storageFile = $dataDir . '/honeypot_messages.json';

        // Create directory if not exists
        if (!is_dir($this->dataDir)) {
            mkdir($this->dataDir, 0755, true);
        }

        // Initialize JSON file if not exists
        if (!file_exists($this->storageFile)) {
            file_put_contents($this->storageFile, json_encode([], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
    }

    /**
     * Add a new message to storage
     */
    public function addMessage(string $username, string $message): array
    {
        // Validate inputs
        if (empty(trim($username)) || empty(trim($message))) {
            return [
                'success' => false,
                'error' => 'Username and message are required'
            ];
        }

        if (strlen($username) < 2 || strlen($username) > 50) {
            return [
                'success' => false,
                'error' => 'Username must be between 2 and 50 characters'
            ];
        }

        if (strlen($message) < 5) {
            return [
                'success' => false,
                'error' => 'Message must be at least 5 characters'
            ];
        }

        try {
            // Read current messages
            $messages = $this->getAllMessages();

            // Detect keywords in message
            $detectedKeywords = $this->detectKeywords($message);

            // Extract URLs from message
            $extractedUrls = $this->extractUrls($message);

            // Analyze each URL for beginner-friendly phishing flags
            $urlDetector = new UrlPhishingDetector();
            $urlAnalyses = $urlDetector->analyzeUrls($extractedUrls);

            // Risk scoring (based on detected keywords + extracted URLs)
            $scorer = new HoneypotRiskScorer($urlDetector);
            $risk = $scorer->score($detectedKeywords, $extractedUrls);

            // Create new message record
            $newMessage = [
                'id' => $this->nextId($messages),
                'username' => (string) $username,
                'message' => (string) $message,
                'detected_keywords' => $detectedKeywords,
                'keyword_count' => count($detectedKeywords),
                'extracted_urls' => $extractedUrls,
                'url_analysis' => $urlAnalyses,
                'url_count' => count($extractedUrls),
                'risk_score' => (int) ($risk['total_score'] ?? 0),
                'risk_level' => strtoupper((string) ($risk['risk_level'] ?? 'LOW')),
                'timestamp' => date('Y-m-d H:i:s'),
                'received_at' => time()
            ];

            // Add to messages array
            $messages[] = $newMessage;

            // Save back to file
            $this->saveMessages($messages);

            // Log analyzed results (separate JSON log)
            $logger = new HoneypotAnalysisLogger($this->dataDir);
            $logger->log([
                'id' => $newMessage['id'],
                'username' => $newMessage['username'],
                'message' => $newMessage['message'],
                'detected_keywords' => $detectedKeywords,
                'urls' => $extractedUrls,
                'url_analysis' => $urlAnalyses,
                'risk_score' => $newMessage['risk_score'],
                'risk_level' => $newMessage['risk_level'],
                'timestamp' => $newMessage['timestamp']
            ]);

            return [
                'success' => true,
                'message' => 'Message saved successfully',
                'data' => [
                    'id' => $newMessage['id'],
                    'username' => $newMessage['username'],
                    'timestamp' => $newMessage['timestamp'],
                    'detected_keywords' => $detectedKeywords,
                    'keyword_count' => count($detectedKeywords),
                    'extracted_urls' => $extractedUrls,
                    'url_analysis' => $urlAnalyses,
                    'url_count' => count($extractedUrls),
                    'risk_score' => $newMessage['risk_score'],
                    'risk_level' => $newMessage['risk_level']
                ]
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Failed to save message: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Get all messages from storage
     */
    public function getAllMessages(): array
    {
        if (!file_exists($this->storageFile)) {
            return [];
        }

        $content = file_get_contents($this->storageFile);
        if ($content === false) {
            return [];
        }

        $messages = json_decode($content, true);
        return is_array($messages) ? $messages : [];
    }

    /**
     * Get recent messages (limited)
     */
    public function getRecentMessages(int $limit = 20): array
    {
        $messages = $this->getAllMessages();
        return array_slice($messages, -$limit);
    }

    /**
     * Get message count
     */
    public function getMessageCount(): int
    {
        return count($this->getAllMessages());
    }

    /**
     * Detect suspicious keywords in message
     */
    public function detectKeywords(string $message): array
    {
        $detected = [];
        $messageLower = strtolower($message);

        foreach ($this->suspiciousKeywords as $keyword) {
            if (stripos($messageLower, $keyword) !== false) {
                $detected[] = $keyword;
            }
        }

        return array_values(array_unique($detected));
    }

    /**
     * Extract URLs from message (http and https)
     */
    public function extractUrls(string $message): array
    {
        $urls = [];

        // Regex pattern to match http and https URLs
        $pattern = '#https?://[^\s<>"{}|\\^`\[\]]*[a-zA-Z0-9/]#i';

        if (preg_match_all($pattern, $message, $matches)) {
            $urls = array_unique($matches[0]);
            // Re-index array to ensure consistent keys
            $urls = array_values($urls);
        }

        return $urls;
    }

    /**
     * Save messages back to file
     */
    private function saveMessages(array $messages): void
    {
        $jsonContent = json_encode($messages, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (file_put_contents($this->storageFile, $jsonContent) === false) {
            throw new Exception('Failed to write to storage file');
        }
    }

    /**
     * Pick the next ID without reusing IDs after records are deleted manually.
     */
    private function nextId(array $messages): int
    {
        $maxId = 0;

        foreach ($messages as $message) {
            $maxId = max($maxId, (int) ($message['id'] ?? 0));
        }

        return $maxId + 1;
    }

    /**
     * Get storage file path (for debugging)
     */
    public function getStoragePath(): string
    {
        return $this->storageFile;
    }

    /**
     * Get suspicious keywords list
     */
    public function getSuspiciousKeywords(): array
    {
        return $this->suspiciousKeywords;
    }

    /**
     * Clear all messages (admin only)
     */
    public function clearAll(): bool
    {
        return file_put_contents($this->storageFile, json_encode([], JSON_PRETTY_PRINT)) !== false;
    }
}
