<?php
declare(strict_types=1);

/**
 * Database access for the fake profile honeypot module.
 */
class FakeProfileRepository
{
    public function __construct(private PDO $pdo)
    {
    }

    public function ensureTables(): void
    {
        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_fake_profiles (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) NOT NULL UNIQUE,
                bio TEXT NOT NULL,
                profile_type VARCHAR(30) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_fake_conversations (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                profile_id INT UNSIGNED NOT NULL,
                sender_username VARCHAR(80) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_fake_conversation (profile_id, sender_username),
                INDEX idx_fake_conversation_profile (profile_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_fake_messages (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                conversation_id INT UNSIGNED NOT NULL,
                profile_id INT UNSIGNED NOT NULL,
                sender_username VARCHAR(80) NOT NULL,
                message_text TEXT NOT NULL,
                keywords_json JSON NOT NULL,
                urls_json JSON NOT NULL,
                url_analysis_json JSON NOT NULL,
                risk_score INT NOT NULL DEFAULT 0,
                risk_level VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_fake_message_profile (profile_id),
                INDEX idx_fake_message_sender (sender_username),
                INDEX idx_fake_message_risk (risk_level)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    public function createProfile(string $username, string $bio, string $profileType): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_fake_profiles (username, bio, profile_type)
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
            ->query('SELECT id, username, bio, profile_type, created_at FROM honeypot_fake_profiles ORDER BY created_at DESC')
            ->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    public function findOrCreateConversation(int $profileId, string $senderUsername): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT id FROM honeypot_fake_conversations
             WHERE profile_id = :profile_id AND sender_username = :sender_username
             LIMIT 1'
        );
        $stmt->execute([
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
        ]);
        $conversationId = (int) ($stmt->fetchColumn() ?: 0);

        if ($conversationId > 0) {
            $this->pdo->prepare('UPDATE honeypot_fake_conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = :id')
                ->execute(['id' => $conversationId]);
            return $conversationId;
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_fake_conversations (profile_id, sender_username)
             VALUES (:profile_id, :sender_username)'
        );
        $stmt->execute([
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @param string[] $keywords
     * @param string[] $urls
     * @param array<int,array<string,mixed>> $urlAnalysis
     */
    public function addMessage(
        int $conversationId,
        int $profileId,
        string $senderUsername,
        string $messageText,
        array $keywords,
        array $urls,
        array $urlAnalysis,
        int $riskScore,
        string $riskLevel
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO honeypot_fake_messages
                (conversation_id, profile_id, sender_username, message_text, keywords_json, urls_json, url_analysis_json, risk_score, risk_level)
             VALUES
                (:conversation_id, :profile_id, :sender_username, :message_text, :keywords_json, :urls_json, :url_analysis_json, :risk_score, :risk_level)'
        );
        $stmt->execute([
            'conversation_id' => $conversationId,
            'profile_id' => $profileId,
            'sender_username' => $senderUsername,
            'message_text' => $messageText,
            'keywords_json' => json_encode($keywords, JSON_UNESCAPED_SLASHES),
            'urls_json' => json_encode($urls, JSON_UNESCAPED_SLASHES),
            'url_analysis_json' => json_encode($urlAnalysis, JSON_UNESCAPED_SLASHES),
            'risk_score' => $riskScore,
            'risk_level' => $riskLevel,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @return array<string,int>
     */
    public function stats(): array
    {
        return [
            'total_profiles' => (int) ($this->pdo->query('SELECT COUNT(*) FROM honeypot_fake_profiles')->fetchColumn() ?: 0),
            'total_messages' => (int) ($this->pdo->query('SELECT COUNT(*) FROM honeypot_fake_messages')->fetchColumn() ?: 0),
            'high_risk_messages' => (int) ($this->pdo->query("SELECT COUNT(*) FROM honeypot_fake_messages WHERE risk_level = 'HIGH'")->fetchColumn() ?: 0),
        ];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function recentMessages(int $limit = 12): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT m.*, p.username AS profile_username, p.profile_type
             FROM honeypot_fake_messages m
             JOIN honeypot_fake_profiles p ON p.id = m.profile_id
             ORDER BY m.created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function allMessages(): array
    {
        return $this->pdo
            ->query('SELECT sender_username, keywords_json, urls_json, risk_level FROM honeypot_fake_messages ORDER BY created_at DESC')
            ->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }
}
