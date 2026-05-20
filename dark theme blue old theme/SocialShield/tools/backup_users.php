<?php
// PhishTrace: backup only the users table into SQL + CSV.
// Run manually when you want a restore point.
//
// Usage (PowerShell):
// C:\laragon\bin\php\php-8.3.30-Win32-vs16-x64\php.exe C:\laragon\www\socialshield\tools\backup_users.php

declare(strict_types=1);

require_once __DIR__ . '/../includes/db.php';

/**
 * Convert DB value to SQL literal safely.
 */
function toSqlValue(PDO $pdo, mixed $value): string
{
    if ($value === null) {
        return 'NULL';
    }

    return $pdo->quote((string) $value);
}

try {
    $pdo = getPDO();

    $backupDir = realpath(__DIR__ . '/..') . DIRECTORY_SEPARATOR . 'backups';
    if (!is_dir($backupDir) && !mkdir($backupDir, 0775, true) && !is_dir($backupDir)) {
        throw new RuntimeException('Could not create backups directory.');
    }

    $timestamp = date('Ymd_His');
    $sqlPath = $backupDir . DIRECTORY_SEPARATOR . "users_{$timestamp}.sql";
    $csvPath = $backupDir . DIRECTORY_SEPARATOR . "users_{$timestamp}.csv";

    $columnsStmt = $pdo->query('DESCRIBE users');
    $columns = [];
    foreach ($columnsStmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $columns[] = (string) $row['Field'];
    }

    if ($columns === []) {
        throw new RuntimeException('No columns found in users table.');
    }

    $createTableRow = $pdo->query('SHOW CREATE TABLE users')->fetch(PDO::FETCH_ASSOC);
    $createTableSql = (string) ($createTableRow['Create Table'] ?? '');
    if ($createTableSql === '') {
        throw new RuntimeException('Could not read users table schema.');
    }

    $usersStmt = $pdo->query('SELECT * FROM users ORDER BY id ASC');
    $users = $usersStmt->fetchAll(PDO::FETCH_ASSOC);

    $columnList = implode(', ', array_map(static fn(string $c): string => "`{$c}`", $columns));

    $sql = [];
    $sql[] = '-- PhishTrace users backup';
    $sql[] = '-- Created at: ' . date('Y-m-d H:i:s');
    $sql[] = 'SET NAMES utf8mb4;';
    $sql[] = '';
    $sql[] = '-- Schema';
    $sql[] = $createTableSql . ';';
    $sql[] = '';
    $sql[] = '-- Data';

    foreach ($users as $user) {
        $values = [];
        foreach ($columns as $column) {
            $values[] = toSqlValue($pdo, $user[$column] ?? null);
        }

        $sql[] = "INSERT INTO `users` ({$columnList}) VALUES (" . implode(', ', $values) . ")"
            . " ON DUPLICATE KEY UPDATE " . implode(', ', array_map(
                static fn(string $c): string => "`{$c}` = VALUES(`{$c}`)",
                $columns
            )) . ';';
    }

    file_put_contents($sqlPath, implode(PHP_EOL, $sql) . PHP_EOL);

    $csvHandle = fopen($csvPath, 'wb');
    if ($csvHandle === false) {
        throw new RuntimeException('Could not create CSV backup file.');
    }

    fputcsv($csvHandle, $columns);
    foreach ($users as $user) {
        $row = [];
        foreach ($columns as $column) {
            $row[] = $user[$column] ?? null;
        }
        fputcsv($csvHandle, $row);
    }
    fclose($csvHandle);

    echo 'Users backup completed.' . PHP_EOL;
    echo 'Rows: ' . count($users) . PHP_EOL;
    echo 'SQL: ' . $sqlPath . PHP_EOL;
    echo 'CSV: ' . $csvPath . PHP_EOL;
} catch (Throwable $exception) {
    echo 'Users backup failed: ' . $exception->getMessage() . PHP_EOL;
    exit(1);
}
