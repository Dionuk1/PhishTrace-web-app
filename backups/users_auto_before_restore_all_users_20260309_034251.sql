-- SocialShield automatic users backup
-- Reason: before_restore_all_users
-- Created at: 2026-03-09 03:42:51
SET NAMES utf8mb4;

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
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('1', 'SocialShield Admin', 'admin@socialshield.local', '$2y$10$TcET6usv0n.e2nFc7b3bDe0Tmc6lY9h94VqVq/996uM5dh/ghEKl6', 'admin', '0', '2026-03-09 04:29:44') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('2', 'Student Demo', 'student@socialshield.local', '$2y$10$EeH.x0d3.tV28dscL4chAu7D4qtAJJjoisDoMD.uJb6ZZYkURbIOu', 'user', '0', '2026-03-09 04:29:44') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `security_score`, `created_at`) VALUES ('3', 'L1ghterVibes', 'l1ghter@socialshield.local', '$2y$10$At808NnooJsW6bAxOqrQIeJ5EYX6ao4T12lF25CuwZ4N69Sj1LZnm', 'user', '0', '2026-03-09 04:37:05') ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `name` = VALUES(`name`), `email` = VALUES(`email`), `password_hash` = VALUES(`password_hash`), `role` = VALUES(`role`), `security_score` = VALUES(`security_score`), `created_at` = VALUES(`created_at`);
