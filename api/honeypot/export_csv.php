<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/HoneypotJsonStorage.php';
requireLogin();
requireAdmin();

$storage = new HoneypotJsonStorage(__DIR__ . '/../../data');
$messages = $storage->getAllMessages();

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="honeypot_logs.csv"');

$output = fopen('php://output', 'w');
if ($output === false) {
    exit;
}

fputcsv($output, ['id', 'username', 'message', 'detected_keywords', 'urls', 'risk_score', 'risk_level', 'timestamp']);

foreach ($messages as $message) {
    fputcsv($output, [
        (int) ($message['id'] ?? 0),
        (string) ($message['username'] ?? ''),
        (string) ($message['message'] ?? ''),
        implode('|', $message['detected_keywords'] ?? []),
        implode('|', $message['extracted_urls'] ?? []),
        (int) ($message['risk_score'] ?? 0),
        strtoupper((string) ($message['risk_level'] ?? 'LOW')),
        (string) ($message['timestamp'] ?? ''),
    ]);
}
