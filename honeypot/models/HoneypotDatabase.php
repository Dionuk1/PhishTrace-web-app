<?php
declare(strict_types=1);

class HoneypotDatabase
{
    public function __construct(private PDO $pdo)
    {
    }

    /**
     * Create only the new honeypot tables. Existing app tables are not changed.
     */
    public function ensureTables(): void
    {
        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_profiles (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) NOT NULL UNIQUE,
                bio TEXT NOT NULL,
                profile_type VARCHAR(30) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_conversations (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                profile_id INT UNSIGNED NOT NULL,
                sender_username VARCHAR(80) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uq_honeypot_conversation (profile_id, sender_username),
                INDEX idx_honeypot_conversations_profile (profile_id),
                CONSTRAINT fk_honeypot_conversations_profile
                    FOREIGN KEY (profile_id) REFERENCES honeypot_profiles(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_messages (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                conversation_id INT UNSIGNED NOT NULL,
                profile_id INT UNSIGNED NOT NULL,
                sender_username VARCHAR(80) NOT NULL,
                message_text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_honeypot_messages_conversation (conversation_id),
                INDEX idx_honeypot_messages_profile (profile_id),
                INDEX idx_honeypot_messages_sender (sender_username),
                CONSTRAINT fk_honeypot_messages_conversation
                    FOREIGN KEY (conversation_id) REFERENCES honeypot_conversations(id) ON DELETE CASCADE,
                CONSTRAINT fk_honeypot_messages_profile
                    FOREIGN KEY (profile_id) REFERENCES honeypot_profiles(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_analysis_logs (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                message_id INT UNSIGNED NOT NULL,
                keywords_detected JSON NOT NULL,
                urls_detected JSON NOT NULL,
                risk_score INT NOT NULL DEFAULT 0,
                risk_level VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_honeypot_analysis_message (message_id),
                INDEX idx_honeypot_analysis_risk (risk_level),
                CONSTRAINT fk_honeypot_analysis_message
                    FOREIGN KEY (message_id) REFERENCES honeypot_messages(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS honeypot_attacker_stats (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                sender_username VARCHAR(80) NOT NULL UNIQUE,
                total_messages INT UNSIGNED NOT NULL DEFAULT 0,
                total_urls INT UNSIGNED NOT NULL DEFAULT 0,
                suspicion_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_honeypot_attacker_level (suspicion_level)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }
}
