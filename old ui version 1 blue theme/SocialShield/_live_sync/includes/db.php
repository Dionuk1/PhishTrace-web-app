<?php
// Database connection helper for PDO (PHP 8.x compatible).
// Bootstrap is intentionally non-destructive so login data and scans
// are never dropped or rebuilt automatically.

declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * Check whether a table can be read.
 */
function isTableUsable(PDO $pdo, string $table): bool
{
    try {
        $pdo->query("SELECT 1 FROM `$table` LIMIT 1");
        return true;
    } catch (PDOException $exception) {
        return false;
    }
}

/**
 * Create core tables if they are missing or broken.
 */
function ensureCoreTables(PDO $pdo): void
{
    // Only create missing tables. Never drop or recreate existing ones.

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('user','admin') NOT NULL DEFAULT 'user',
            security_score INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scans (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id INT UNSIGNED NOT NULL,
            url TEXT NOT NULL,
            risk_score INT NOT NULL DEFAULT 0,
            status ENUM('Safe','Suspicious','Dangerous') NOT NULL,
            reasons TEXT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS blacklist_domains (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255) NOT NULL UNIQUE,
            reason VARCHAR(255) DEFAULT NULL,
            source VARCHAR(255) DEFAULT 'Manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS whitelist_domains (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS security_tips (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT NOT NULL,
            category VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS threat_feed (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            url TEXT NOT NULL,
            domain VARCHAR(255) NOT NULL,
            source VARCHAR(100) NOT NULL DEFAULT 'OpenPhish',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_threat_feed_url (url(768)),
            INDEX idx_threat_feed_domain (domain)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS agent_logs (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            agent_name VARCHAR(120) NOT NULL,
            entries_imported INT UNSIGNED NOT NULL DEFAULT 0,
            status VARCHAR(30) NOT NULL,
            run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
}

/**
 * Prefer a clean `phishtrace` database and create it if needed.
 * Falls back to existing `social shield` only when create permission is unavailable.
 */
function resolveDatabaseName(PDO $serverPdo): string
{
    try {
        $serverPdo->exec('CREATE DATABASE IF NOT EXISTS `' . DB_NAME . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci');
        return DB_NAME;
    } catch (PDOException $exception) {
        // Fallback for restricted users without CREATE DATABASE permission.
    }

    foreach (['social shield', DB_NAME] as $candidate) {
        $stmt = $serverPdo->prepare(
            'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = :name LIMIT 1'
        );
        $stmt->execute(['name' => $candidate]);
        if ($stmt->fetchColumn()) {
            return $candidate;
        }
    }

    return DB_NAME;
}

/**
 * Create demo users when users table is empty.
 */
function ensureDemoAdmin(PDO $pdo): void
{
    $count = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($count > 0) {
        return;
    }

    $stmt = $pdo->prepare(
        'INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :password_hash, :role)'
    );
    $stmt->execute([
        'name' => 'PhishTrace Admin',
        'email' => 'admin@phishtrace.local',
        'password_hash' => password_hash('Admin123!', PASSWORD_DEFAULT),
        'role' => 'admin',
    ]);
    $stmt->execute([
        'name' => 'Student Demo',
        'email' => 'student@phishtrace.local',
        'password_hash' => password_hash('Student123!', PASSWORD_DEFAULT),
        'role' => 'user',
    ]);
}

/**
 * Add default security tips if they do not already exist.
 */
function ensureSeedTips(PDO $pdo): void
{
    $tips = [
        ['Enable 2FA Everywhere', 'Turn on two-factor authentication on every social account.', 'Account Protection'],
        ['Use Unique Passwords', 'Use different strong passwords for each social platform.', 'Account Protection'],
        ['Check URL Before Login', 'Always verify domain spelling before entering credentials.', 'Phishing Defense'],
        ['Verify Account Messages', 'Confirm alerts through official websites or apps before clicking any message link.', 'Phishing Defense'],
        ['Do Not Trust Urgent DMs', 'Pause before clicking links that create urgency.', 'Scam Awareness'],
        ['Avoid Fake Giveaways', 'Be careful with reward/bonus claims asking for logins or wallet details.', 'Scam Awareness'],
        ['Review Privacy Settings', 'Check profile visibility and permissions regularly.', 'Privacy'],
        ['Limit Public Personal Data', 'Do not post phone number, address, ID details, or travel plans publicly.', 'Privacy'],
        ['Review Connected Apps', 'Remove third-party apps that no longer need social account access.', 'Privacy'],
        ['Report Suspicious Accounts', 'Report impersonation and phishing pages to protect other users.', 'Community Safety'],
    ];

    $existsStmt = $pdo->prepare('SELECT id FROM security_tips WHERE title = :title LIMIT 1');
    $insertStmt = $pdo->prepare(
        'INSERT INTO security_tips (title, description, category) VALUES (:title, :description, :category)'
    );

    foreach ($tips as $tip) {
        $existsStmt->execute(['title' => $tip[0]]);
        if ($existsStmt->fetch()) {
            continue;
        }

        $insertStmt->execute([
            'title' => $tip[0],
            'description' => $tip[1],
            'category' => $tip[2],
        ]);
    }
}

/**
 * Return a shared PDO instance for all pages.
 */
function getPDO(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ];

    try {
        $serverPdo = new PDO(
            sprintf('mysql:host=%s;charset=%s', DB_HOST, DB_CHARSET),
            DB_USER,
            DB_PASS,
            $options
        );
        $databaseName = resolveDatabaseName($serverPdo);

        $pdo = new PDO(
            sprintf('mysql:host=%s;dbname=%s;charset=%s', DB_HOST, $databaseName, DB_CHARSET),
            DB_USER,
            DB_PASS,
            $options
        );

        ensureCoreTables($pdo);
        ensureDemoAdmin($pdo);
        ensureSeedTips($pdo);
    } catch (PDOException $exception) {
        http_response_code(500);
        exit(
            'Database connection failed.' . PHP_EOL .
            '1) Open phpMyAdmin and create database phishtrace (or social shield)' . PHP_EOL .
            '2) Import C:\\xampp\\htdocs\\phishtrace\\database\\phishtrace.sql' . PHP_EOL .
            '3) Open http://localhost/phishtrace'
        );
    }

    return $pdo;
}

