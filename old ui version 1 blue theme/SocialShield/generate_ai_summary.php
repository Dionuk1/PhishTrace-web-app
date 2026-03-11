<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/functions.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    redirect('result.php');
}

if (empty($_SESSION['generate_ai_summary_pending'])) {
    redirect('result.php');
}

$analysis = $_SESSION['latest_scan_analysis'] ?? null;
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

$_SESSION['latest_ai_report'] = generateAiSecurityAssistantReport($analysis);
unset($_SESSION['generate_ai_summary_pending']);

redirect('result.php');
