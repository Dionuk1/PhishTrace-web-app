<?php
// SocialShield: backup only the scans table into SQL + CSV.
// Usage:
// C:\laragon\bin\php\php-8.3.30-Win32-vs16-x64\php.exe C:\laragon\www\socialshield\tools\backup_scans.php

declare(strict_types=1);

require_once __DIR__ . '/../includes/functions.php';

try {
    $pdo = getPDO();
    $backup = createScansBackup($pdo, 'manual_backup');
    if ($backup === null) {
        throw new RuntimeException('Could not create scans backup.');
    }

    echo 'Scans backup completed.' . PHP_EOL;
    echo 'Rows: ' . (int) $backup['rows'] . PHP_EOL;
    echo 'SQL: ' . (string) $backup['sql'] . PHP_EOL;
    echo 'CSV: ' . (string) $backup['csv'] . PHP_EOL;
} catch (Throwable $exception) {
    echo 'Scans backup failed: ' . $exception->getMessage() . PHP_EOL;
    exit(1);
}
