<?php
declare(strict_types=1);

require_once __DIR__ . '/../services/AttackerStatsService.php';

class HoneypotRepository
{
    public function __construct(private PDO $pdo)
    {
    }

    public function createProfile(string $username, string $bio, string $profileType): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_profiles (username, bio, profile_type)
             VALUES (:username, :bio, :profile_type)'
        );
        $stmt->execute([
            'username' => $username,
            'bio' => $bio,
            'profile_type' => $profileType,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function profiles(): array
    {
        return $this->pdo
            ->query('SELECT id, username, bio, profile_type, created_at FROM honeypot_profiles ORDER BY created_at DESC')
            ->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    public function findOrCreateConversation(int $profileId, string $senderUsername): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT id FROM honeypot_conversations
             WHERE profile_id = :profile_id AND sender_username = :sender_username
             LIMIT 1'
        );
        $stmt->execute([
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
        ]);

        $conversationId = (int) ($stmt->fetchColumn() ?: 0);
        if ($conversationId > 0) {
            return $conversationId;
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_conversations (profile_id, sender_username)
             VALUES (:profile_id, :sender_username)'
        );
        $stmt->execute([
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function createMessage(int $conversationId, int $profileId, string $senderUsername, string $messageText): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_messages (conversation_id, profile_id, sender_username, message_text)
             VALUES (:conversation_id, :profile_id, :sender_username, :message_text)'
        );
        $stmt->execute([
            'conversation_id' => $conversationId,
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
            'message_text' => $messageText,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @param string[] $keywords
     * @param string[] $urls
     */
    public function createAnalysisLog(int $messageId, array $keywords, array $urls, int $riskScore, string $riskLevel): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_analysis_logs (message_id, keywords_detected, urls_detected, risk_score, risk_level)
             VALUES (:message_id, :keywords_detected, :urls_detected, :risk_score, :risk_level)'
        );
        $stmt->execute([
            'message_id' => $messageId,
            'keywords_detected' => json_encode($keywords, JSON_UNESCAPED_SLASHES),
            'urls_detected' => json_encode($urls, JSON_UNESCAPED_SLASHES),
            'risk_score' => $riskScore,
            'risk_level' => $riskLevel,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function refreshAttackerStats(string $senderUsername): void
    {
        $stmt = $this->pdo->prepare(
            'SELECT m.sender_username, a.keywords_detected, a.urls_detected, a.risk_level
             FROM honeypot_messages m
             JOIN honeypot_analysis_logs a ON a.message_id = m.id
             WHERE m.sender_username = :sender_username'
        );
        $stmt->execute(['sender_username' => $senderUsername]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

        $totalMessages = count($messages);
        $totalUrls = 0;
        $highRiskCount = 0;
        $keywordCounts = [];

        foreach ($messages as $message) {
            $urls = json_decode((string) ($message['urls_detected'] ?? '[]'), true);
            $keywords = json_decode((string) ($message['keywords_detected'] ?? '[]'), true);
            $totalUrls += is_array($urls) ? count($urls) : 0;
            $highRiskCount += ((string) ($message['risk_level'] ?? 'LOW')) === 'HIGH' ? 1 : 0;

            if (is_array($keywords)) {
                foreach ($keywords as $keyword) {
                    $keywordCounts[$keyword] = ($keywordCounts[$keyword] ?? 0) + 1;
                }
            }
        }

        $repeatedKeywordCount = 0;
        foreach ($keywordCounts as $count) {
            if ($count >= 2) {
                $repeatedKeywordCount++;
            }
        }

        $level = (new HoneypotAttackerStatsService())->suspicionLevel(
            $totalMessages,
            $totalUrls,
            $repeatedKeywordCount,
            $highRiskCount
        );

        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_attacker_stats (sender_username, total_messages, total_urls, suspicion_level, last_seen)
             VALUES (:sender_username, :total_messages, :total_urls, :suspicion_level, CURRENT_TIMESTAMP)
             ON DUPLICATE KEY UPDATE
                total_messages = VALUES(total_messages),
                total_urls = VALUES(total_urls),
                suspicion_level = VALUES(suspicion_level),
                last_seen = CURRENT_TIMESTAMP'
        );
        $stmt->execute([
            'sender_username' => $senderUsername,
            'total_messages' => $totalMessages,
            'total_urls' => $totalUrls,
            'suspicion_level' => $level,
        ]);
    }

    /**
     * @return array{total_profiles:int,total_messages:int,high_risk_alerts:int}
     */
    public function dashboardStats(): array
    {
        return [
            'total_profiles' => (int) ($this->pdo->query('SELECT COUNT(*) FROM honeypot_profiles')->fetchColumn() ?: 0),
            'total_messages' => (int) ($this->pdo->query('SELECT COUNT(*) FROM honeypot_messages')->fetchColumn() ?: 0),
            'high_risk_alerts' => (int) ($this->pdo->query("SELECT COUNT(*) FROM honeypot_analysis_logs WHERE risk_level = 'HIGH'")->fetchColumn() ?: 0),
        ];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function recentMessages(int $limit = 12): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT m.id, m.sender_username, m.message_text, m.timestamp, p.username AS profile_username,
                    p.profile_type, a.keywords_detected, a.urls_detected, a.risk_score, a.risk_level
             FROM honeypot_messages m
             JOIN honeypot_profiles p ON p.id = m.profile_id
             JOIN honeypot_analysis_logs a ON a.message_id = m.id
             ORDER BY m.timestamp DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function topAttackers(int $limit = 8): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT sender_username, total_messages, total_urls, suspicion_level, last_seen
             FROM honeypot_attacker_stats
             ORDER BY total_messages DESC, total_urls DESC, last_seen DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function conversationMessages(?int $profileId): array
    {
        if (!$profileId) {
            return [];
        }

        $stmt = $this->pdo->prepare(
            'SELECT m.sender_username, m.message_text, m.timestamp, a.risk_score, a.risk_level
             FROM honeypot_messages m
             JOIN honeypot_analysis_logs a ON a.message_id = m.id
             WHERE m.profile_id = :profile_id
             ORDER BY m.timestamp DESC
             LIMIT 20'
        );
        $stmt->execute(['profile_id' => $profileId]);

        return array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC) ?: []);
    }
}
