-- SocialShield automatic users backup
-- Reason: after_restore_all_users
-- Created at: 2026-03-10 22:07:39
SET NAMES utf8mb4;

-- Schema
CREATE TABLE `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('user','admin') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'user',
  `security_score` int NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('1', 'SocialShield Admin', 'admin@socialshield.local', '$2y$10$8A8IEC6FYepjrLEI9zRU8.WlkfomkX53gq7XTPHVEHg.WBoBXbW4G', 'admin', '0', '2026-03-10 22:38:24') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('2', 'Student Demo', 'student@socialshield.local', '$2y$10$zHrfWb/07kWxGxXDAGWN/eAtWZTxxvaz8Vwptgx4pysE4ky6UuYd2', 'user', '10', '2026-03-10 22:38:24') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('3', 'Codex DB Test', 'codexdb20260310223921@local.test', '$2y$10$HBAl3ix7Bu6YmhHScFPaEOkS2MJBJ4yFID8XCv9iSeJxFo7JEqERu', 'user', '0', '2026-03-10 22:39:22') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('4', 'Codex DB Test', 'codexdb20260310224044@local.test', '$2y$10$Pg0/YdpUoeXpB/uosE664eSQMDQdCQn74UXL859k8ZfMmIgC2IDy2', 'user', '0', '2026-03-10 22:40:45') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('5', 'Codex DB Test', 'codexdb20260310224104@local.test', '$2y$10$.QI1ykOyZBGLakuWA2NgUuO8/4KeToqUbmdDchD2r.FQT0niAMUvC', 'user', '0', '2026-03-10 22:41:04') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
