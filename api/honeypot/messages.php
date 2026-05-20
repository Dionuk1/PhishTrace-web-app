<?php
/**
 * Honeypot Backend API - Get Messages
 * Retrieves stored messages from JSON storage
 *
 * Usage:
 *   GET /api/honeypot/messages.php
 *   GET /api/honeypot/messages.php?limit=10
 *
 *   Response:
 *   {
 *     "success": true,
 *     "total": 42,
 *     "limit": 20,
 *     "messages": [
 *       {
 *         "id": 1,
 *         "username": "john_doe",
 *         "message": "Your message here",
 *         "timestamp": "2026-04-27 14:30:45"
 *       },
 *       ...
 *     ]
 *   }
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');

// Include storage class
require_once __DIR__ . '/HoneypotJsonStorage.php';

try {
    // Only allow GET requests
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        echo json_encode([
            'success' => false,
            'message' => 'Method not allowed. Use GET.'
        ]);
        exit;
    }

    // Get limit parameter (default 20, max 100)
    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 20;
    $limit = min(max($limit, 1), 100); // Ensure between 1 and 100

    // Get data directory
    $dataDir = __DIR__ . '/../../data';

    // Initialize storage
    $storage = new HoneypotJsonStorage($dataDir);

    // Get messages
    $allMessages = $storage->getAllMessages();
    $recentMessages = array_slice($allMessages, -$limit);

    // Return response
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'total' => count($allMessages),
        'limit' => $limit,
        'returned' => count($recentMessages),
        'messages' => array_values($recentMessages)
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Server error: ' . $e->getMessage()
    ]);
}
