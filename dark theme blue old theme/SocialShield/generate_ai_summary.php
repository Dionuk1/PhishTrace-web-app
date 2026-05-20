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
    $user = currentUser();
    if ($user) {
        $pdo = getPDO();
        $stmt = $pdo->prepare('SELECT url FROM scans WHERE user_id = :user_id ORDER BY scanned_at DESC LIMIT 1');
        $stmt->execute(['user_id' => (int) $user['id']]);
        $row = $stmt->fetch();
        if ($row && !empty($row['url'])) {
            $analysis = analyzeUrl((string) $row['url'], $pdo);
            if (is_array($analysis) && !empty($analysis['url'])) {
                $_SESSION['latest_scan_analysis'] = $analysis;
            }
        }
    }
}
if (!is_array($analysis) || empty($analysis['url'])) {
    setFlash('No scan analysis is available for AI summarization.', 'warning');
    redirect('scan.php');
}

$_SESSION['latest_ai_report'] = generateAiSecurityAssistantReport($analysis);
unset($_SESSION['generate_ai_summary_pending']);

redirect('result.php');
