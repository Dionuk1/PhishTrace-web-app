-- SocialShield automatic scans backup
-- Reason: save_scan
-- Created at: 2026-03-09 03:57:45
SET NAMES utf8mb4;

CREATE TABLE `scans` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `url` text NOT NULL,
  `risk_score` int NOT NULL DEFAULT '0',
  `status` enum('Safe','Suspicious','Dangerous') NOT NULL,
  `reasons` text,
  `scanned_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `fk_scans_user` (`user_id`),
  CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `scans` (`id`, `user_id`, `url`, `risk_score`, `status`, `reasons`, `scanned_at`) VALUES ('3', '1', 'https://www.google.com', '0', 'Safe', '[\"No suspicious indicators triggered.\"]', '2026-03-09 04:44:26') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `user_id` = VALUES(`user_id`), `url` = VALUES(`url`), `risk_score` = VALUES(`risk_score`), `status` = VALUES(`status`), `reasons` = VALUES(`reasons`), `scanned_at` = VALUES(`scanned_at`);
INSERT INTO `scans` (`id`, `user_id`, `url`, `risk_score`, `status`, `reasons`, `scanned_at`) VALUES ('4', '1', 'https://github.com@evil-login-check.top/reset', '50', 'Dangerous', '[\"Suspicious keyword(s) detected: login, reset (+15)\",\"URL contains @ symbol which may hide the real domain (+20)\",\"Suspicious top-level domain detected (+15)\"]', '2026-03-09 04:50:53') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `user_id` = VALUES(`user_id`), `url` = VALUES(`url`), `risk_score` = VALUES(`risk_score`), `status` = VALUES(`status`), `reasons` = VALUES(`reasons`), `scanned_at` = VALUES(`scanned_at`);
INSERT INTO `scans` (`id`, `user_id`, `url`, `risk_score`, `status`, `reasons`, `scanned_at`) VALUES ('5', '1', 'http://faceb00k-security-alert.com/login/verify(shouldbedangerous)', '80', 'Dangerous', '[\"URL does not use HTTPS (+20)\",\"Suspicious keyword(s) detected: login, verify (+15)\",\"URL contains login-related path commonly used in phishing pages (+15)\",\"Possible brand impersonation detected (+30)\"]', '2026-03-09 04:52:42') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `user_id` = VALUES(`user_id`), `url` = VALUES(`url`), `risk_score` = VALUES(`risk_score`), `status` = VALUES(`status`), `reasons` = VALUES(`reasons`), `scanned_at` = VALUES(`scanned_at`);
INSERT INTO `scans` (`id`, `user_id`, `url`, `risk_score`, `status`, `reasons`, `scanned_at`) VALUES ('6', '1', 'http://faceb00k-security-alert.com/login/verify(shouldbedangerous)', '80', 'Dangerous', '[\"URL does not use HTTPS (+20)\",\"Suspicious keyword(s) detected: login, verify (+15)\",\"URL contains login-related path commonly used in phishing pages (+15)\",\"Possible brand impersonation detected (+30)\"]', '2026-03-09 04:57:45') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `user_id` = VALUES(`user_id`), `url` = VALUES(`url`), `risk_score` = VALUES(`risk_score`), `status` = VALUES(`status`), `reasons` = VALUES(`reasons`), `scanned_at` = VALUES(`scanned_at`);
