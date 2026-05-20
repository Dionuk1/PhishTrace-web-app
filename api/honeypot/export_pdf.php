<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/HoneypotJsonStorage.php';
requireLogin();
requireAdmin();

$storage = new HoneypotJsonStorage(__DIR__ . '/../../data');
$messages = array_reverse($storage->getAllMessages());

$totalUrls = 0;
$highRiskMessages = 0;
foreach ($messages as $message) {
    $totalUrls += count($message['extracted_urls'] ?? []);
    if (strtoupper((string) ($message['risk_level'] ?? 'LOW')) === 'HIGH') {
        $highRiskMessages++;
    }
}

$report = [
    'generated_at' => date('Y-m-d H:i:s'),
    'total_messages' => count($messages),
    'total_urls' => $totalUrls,
    'high_risk_messages' => $highRiskMessages,
    'messages' => array_slice($messages, 0, 35),
];

$pdf = buildSecurityReportPdf($report);

header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="honeypot_security_report.pdf"');
header('Content-Length: ' . strlen($pdf));
echo $pdf;

/**
 * Build a styled PDF report without third-party libraries.
 *
 * @param array{
 *   generated_at:string,
 *   total_messages:int,
 *   total_urls:int,
 *   high_risk_messages:int,
 *   messages:array<int,array<string,mixed>>
 * } $report
 */
function buildSecurityReportPdf(array $report): string
{
    $pages = paginateReportMessages($report['messages']);

    $objects = [];
    $objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    $objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
    $objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';

    $pageRefs = [];
    $nextObjectId = 5;
    $pageNumber = 1;

    foreach ($pages as $pageLines) {
        $pageObjectId = $nextObjectId++;
        $contentObjectId = $nextObjectId++;
        $pageRefs[] = $pageObjectId . ' 0 R';

        $content = renderReportPage($report, $pageLines, $pageNumber, count($pages));

        $objects[$pageObjectId] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ' . $contentObjectId . ' 0 R >>';
        $objects[$contentObjectId] = '<< /Length ' . strlen($content) . " >>\nstream\n" . $content . "endstream";
        $pageNumber++;
    }

    $objects[2] = '<< /Type /Pages /Kids [' . implode(' ', $pageRefs) . '] /Count ' . count($pageRefs) . ' >>';
    ksort($objects);

    return assemblePdf($objects);
}

/**
 * @param array<int,array<string,mixed>> $messages
 * @return array<int,array<int,array<string,mixed>>>
 */
function paginateReportMessages(array $messages): array
{
    if ($messages === []) {
        return [[]];
    }

    return array_chunk($messages, 5);
}

/**
 * @param array<string,mixed> $report
 * @param array<int,array<string,mixed>> $messages
 */
function renderReportPage(array $report, array $messages, int $pageNumber, int $pageCount): string
{
    $content = '';

    // Header band
    $content .= "0.06 0.15 0.28 rg\n0 742 612 100 re f\n";
    $content .= pdfText('Social Media Honeypot', 42, 800, 20, true, [1, 1, 1]);
    $content .= pdfText('Suspicious Message & Phishing Detection Report', 42, 774, 12, false, [0.86, 0.93, 1]);
    $content .= pdfText('Generated: ' . (string) $report['generated_at'], 420, 775, 9, false, [0.86, 0.93, 1]);

    if ($pageNumber === 1) {
        $content .= renderSummaryCards(
            (int) $report['total_messages'],
            (int) $report['total_urls'],
            (int) $report['high_risk_messages']
        );
    }

    $y = $pageNumber === 1 ? 596 : 704;
    $content .= pdfText('Recent Honeypot Messages', 42, $y + 22, 14, true, [0.08, 0.12, 0.18]);

    if ($messages === []) {
        $content .= pdfText('No honeypot messages have been recorded yet.', 42, $y - 10, 11, false, [0.35, 0.39, 0.45]);
    }

    foreach ($messages as $message) {
        $content .= renderMessageBlock($message, 42, $y);
        $y -= 104;
    }

    $content .= "0.72 0.75 0.80 RG\n42 38 m 570 38 l S\n";
    $content .= pdfText('Page ' . $pageNumber . ' of ' . $pageCount, 506, 22, 9, false, [0.35, 0.39, 0.45]);

    return $content;
}

function renderSummaryCards(int $totalMessages, int $totalUrls, int $highRiskMessages): string
{
    $cards = [
        ['label' => 'Total Messages', 'value' => (string) $totalMessages, 'color' => [0.07, 0.32, 0.60]],
        ['label' => 'Total URLs', 'value' => (string) $totalUrls, 'color' => [0.06, 0.45, 0.44]],
        ['label' => 'HIGH Risk', 'value' => (string) $highRiskMessages, 'color' => [0.74, 0.11, 0.16]],
    ];

    $content = '';
    $x = 42;

    foreach ($cards as $card) {
        [$r, $g, $b] = $card['color'];
        $content .= "0.97 0.98 1 rg\n$x 640 160 70 re f\n";
        $content .= "$r $g $b RG\n$x 640 160 70 re S\n";
        $content .= pdfText($card['label'], $x + 14, 686, 10, false, [0.35, 0.39, 0.45]);
        $content .= pdfText($card['value'], $x + 14, 655, 24, true, $card['color']);
        $x += 182;
    }

    return $content;
}

/**
 * @param array<string,mixed> $message
 */
function renderMessageBlock(array $message, int $x, int $y): string
{
    $riskLevel = strtoupper((string) ($message['risk_level'] ?? 'LOW'));
    $riskScore = (int) ($message['risk_score'] ?? 0);
    $riskColor = riskColor($riskLevel);
    $background = $riskLevel === 'HIGH' ? [1, 0.94, 0.94] : [0.99, 0.995, 1];
    [$br, $bg, $bb] = $background;
    [$rr, $rg, $rb] = $riskColor;

    $username = (string) ($message['username'] ?? 'Unknown');
    $timestamp = (string) ($message['timestamp'] ?? '');
    $keywords = implode(', ', $message['detected_keywords'] ?? []);
    $urls = implode(', ', $message['extracted_urls'] ?? []);
    $messageText = (string) ($message['message'] ?? '');

    $content = "$br $bg $bb rg\n$x " . ($y - 76) . " 528 88 re f\n";
    $content .= "0.83 0.87 0.93 RG\n$x " . ($y - 76) . " 528 88 re S\n";
    $content .= "$rr $rg $rb rg\n" . ($x + 438) . " " . ($y - 2) . " 86 22 re f\n";
    $content .= pdfText($riskLevel === 'HIGH' ? 'HIGH RISK' : $riskLevel, $x + 448, $y + 4, 9, true, [1, 1, 1]);

    $content .= pdfText('#' . (int) ($message['id'] ?? 0) . '  ' . $username, $x + 12, $y + 4, 12, true, [0.08, 0.12, 0.18]);
    $content .= pdfText('Score: ' . $riskScore . '   Time: ' . $timestamp, $x + 12, $y - 14, 9, false, [0.35, 0.39, 0.45]);
    $content .= pdfText('Keywords: ' . ($keywords !== '' ? $keywords : 'None'), $x + 12, $y - 32, 9, false, [0.18, 0.22, 0.29]);
    $content .= pdfText('URLs: ' . ($urls !== '' ? shortenText($urls, 92) : 'None'), $x + 12, $y - 48, 9, false, [0.18, 0.22, 0.29]);

    $messageLines = wrapPdfLine('Message: ' . $messageText, 92);
    $content .= pdfText(shortenText($messageLines[0] ?? 'Message:', 100), $x + 12, $y - 64, 9, false, [0.18, 0.22, 0.29]);

    return $content;
}

/**
 * @return array{0:float,1:float,2:float}
 */
function riskColor(string $riskLevel): array
{
    if ($riskLevel === 'HIGH') {
        return [0.74, 0.11, 0.16];
    }

    if ($riskLevel === 'MEDIUM') {
        return [0.72, 0.43, 0.04];
    }

    return [0.09, 0.50, 0.28];
}

/**
 * @param array{0:float,1:float,2:float} $color
 */
function pdfText(string $text, int $x, int $y, int $size = 10, bool $bold = false, array $color = [0, 0, 0]): string
{
    [$r, $g, $b] = $color;

    return "BT\n$r $g $b rg\n/" . ($bold ? 'F2' : 'F1') . " $size Tf\n$x $y Td\n(" . escapePdfText($text) . ") Tj\nET\n";
}

/**
 * @param array<int,string> $objects
 */
function assemblePdf(array $objects): string
{
    $pdf = "%PDF-1.4\n";
    $offsets = [0 => 0];

    foreach ($objects as $objectId => $body) {
        $offsets[$objectId] = strlen($pdf);
        $pdf .= $objectId . " 0 obj\n" . $body . "\nendobj\n";
    }

    $xrefOffset = strlen($pdf);
    $objectCount = max(array_keys($objects)) + 1;
    $pdf .= "xref\n0 " . $objectCount . "\n";
    $pdf .= "0000000000 65535 f \n";

    for ($i = 1; $i < $objectCount; $i++) {
        $pdf .= sprintf('%010d 00000 n ', $offsets[$i] ?? 0) . "\n";
    }

    $pdf .= "trailer\n<< /Size " . $objectCount . " /Root 1 0 R >>\n";
    $pdf .= "startxref\n" . $xrefOffset . "\n%%EOF";

    return $pdf;
}

function shortenText(string $text, int $maxLength): string
{
    if (strlen($text) <= $maxLength) {
        return $text;
    }

    return substr($text, 0, $maxLength - 3) . '...';
}

/**
 * @return string[]
 */
function wrapPdfLine(string $line, int $maxLength): array
{
    $line = preg_replace('/\s+/', ' ', trim($line)) ?? '';

    if ($line === '') {
        return [''];
    }

    return explode("\n", wordwrap($line, $maxLength, "\n", true));
}

function escapePdfText(string $text): string
{
    $text = str_replace(["\r", "\n", "\t"], ' ', $text);
    $text = iconv('UTF-8', 'ISO-8859-1//TRANSLIT//IGNORE', $text) ?: $text;

    return str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $text);
}
