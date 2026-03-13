-- SocialShield automatic scans backup
-- Reason: before_restore_all_scans
-- Created at: 2026-03-10 22:17:40
SET NAMES utf8mb4;

-- Schema
CREATE TABLE `scans` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `url` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `domain` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `risk_score` int NOT NULL DEFAULT '0',
  `status` enum('Safe','Suspicious','Dangerous') COLLATE utf8mb4_unicode_ci NOT NULL,
  `reasons` text COLLATE utf8mb4_unicode_ci,
  `scanned_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `fk_scans_user` (`user_id`),
  CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data
INSERT INTO `scans` (`id`, `user_id`, `url`, `domain`, `risk_score`, `status`, `reasons`, `scanned_at`) VALUES ('1', '2', 'https://www.google.com', 'google.com', '0', 'Safe', '[\"No suspicious indicators triggered.\"]', '2026-03-10 23:07:14') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `user_id` = VALUES(`user_id`), `url` = VALUES(`url`), `domain` = VALUES(`domain`), `risk_score` = VALUES(`risk_score`), `status` = VALUES(`status`), `reasons` = VALUES(`reasons`), `scanned_at` = VALUES(`scanned_at`);
