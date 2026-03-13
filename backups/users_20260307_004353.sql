-- SocialShield users backup
-- Created at: 2026-03-07 00:43:53
SET NAMES utf8mb4;

-- Schema
CREATE TABLE `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('user','admin') NOT NULL DEFAULT 'user',
  `security_score` int NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Data
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('1', 'SocialShield Admin', 'admin@socialshield.local', '$2y$10$ak9TadNZmab4i0at0XNPPuhZebOyAzRBv/DWSbuTS8RtqFX9iRPoG', 'admin', '15', '2026-03-06 23:36:39') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('2', 'Student Demo', 'student@socialshield.local', '$2y$10$4xcZsEALEVvp8eNvgRx0xuyjQ4ymqkb3V0kQ8rgYnbZyNywreYNZm', 'user', '0', '2026-03-06 23:36:39') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
