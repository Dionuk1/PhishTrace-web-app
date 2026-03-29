-- PhishTrace database schema + demo seed data
-- Import this file in phpMyAdmin after creating the "phishtrace" database.

SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS security_tips;
DROP TABLE IF EXISTS blacklist_domains;
DROP TABLE IF EXISTS whitelist_domains;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    security_score INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    url TEXT NOT NULL,
    domain VARCHAR(255) DEFAULT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    status ENUM('Safe', 'Suspicious', 'Dangerous') NOT NULL,
    reasons TEXT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE blacklist_domains (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    reason VARCHAR(255) DEFAULT NULL,
    source VARCHAR(255) DEFAULT 'Manual',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE whitelist_domains (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE security_tips (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Demo users:
-- admin@phishtrace.local / password
-- student@phishtrace.local / password
INSERT INTO users (name, email, password_hash, role) VALUES
('Admin User', 'admin@phishtrace.local', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin'),
('Student Demo', 'student@phishtrace.local', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user');

INSERT INTO blacklist_domains (domain, reason, source) VALUES
('faceb00k-security-alert.com', 'Impersonation of social media login page', 'Demo Seed'),
('verify-wallet-now.net', 'Wallet credential phishing campaign', 'Demo Seed'),
('claim-free-bonus-gift.xyz', 'Prize scam and malware redirects', 'Demo Seed'),
('login-instagram-help.center', 'Fake account recovery phishing', 'Demo Seed');

INSERT INTO whitelist_domains (domain) VALUES
('facebook.com'),
('instagram.com'),
('x.com'),
('linkedin.com'),
('github.com');

INSERT INTO security_tips (title, description, category) VALUES
('Enable 2FA Everywhere', 'Turn on two-factor authentication on every social network to protect accounts even if your password is stolen.', 'Account Protection'),
('Check URL Before Login', 'Always inspect the domain carefully before typing credentials. Small spelling changes can indicate phishing.', 'Phishing Defense'),
('Use Unique Passwords', 'Never reuse one password across platforms. Use a password manager to generate strong unique passwords.', 'Account Protection'),
('Review Privacy Settings Monthly', 'Audit who can see your posts, stories, and personal details at least once every month.', 'Privacy'),
('Do Not Trust Urgent DMs', 'Scammers often create urgency ("verify now", "limited time"). Pause and verify through official channels.', 'Scam Awareness'),
('Limit Public Personal Data', 'Avoid sharing phone numbers, full birth dates, addresses, and travel plans publicly.', 'Privacy'),
('Report Suspicious Content', 'Use in-app report tools for suspicious links, fake giveaways, or impersonation accounts.', 'Community Safety'),
('Update Devices and Browsers', 'Install security updates quickly to reduce risk from known browser and OS vulnerabilities.', 'Device Security');

SET FOREIGN_KEY_CHECKS = 1;

