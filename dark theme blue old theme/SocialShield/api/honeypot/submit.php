<?php
/**
 * Honeypot Backend API Endpoint
 * Receives messages from frontend and stores them in JSON
 * Automatically detects suspicious keywords and extracts URLs
 * 
 * Usage:
 *   POST /api/honeypot/submit.php
 *   
 *   Body (JSON):
 *   {
 *     "username": "john_doe",
 *     "message": "Your message here"
 *   }
 * 
 *   Response:
 *   {
 *     "success": true,
 *     "message": "Message saved successfully",
 *     "data": {
 *       "id": 1,
 *       "username": "john_doe",
 *       "timestamp": "2026-04-27 14:30:45",
 *       "detected_keywords": ["verify", "click"],
 *       "keyword_count": 2,
 *       "extracted_urls": ["https://example.com"],
 *       "url_count": 1
 *     }
 *   }
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Include storage class
require_once __DIR__ . '/HoneypotJsonStorage.php';

// Initialize response array
$response = [
    'success' => false,
    'message' => '',
    'data' => []
];

try {
    // Only allow POST requests
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        $response['message'] = 'Method not allowed. Use POST.';
        echo json_encode($response);
        exit;
    }

    // Get POST data (support both form data and JSON)
    $input = $_POST;
    
    // If content-type is JSON, parse it
    if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
        $jsonInput = json_decode(file_get_contents('php://input'), true);
        if (is_array($jsonInput)) {
            $input = $jsonInput;
        }
    }

    // Extract and validate inputs
    $username = isset($input['username']) ? trim((string) $input['username']) : '';
    $message = isset($input['message']) ? trim((string) $input['message']) : '';

    // Get data directory (relative to this file)
    $dataDir = __DIR__ . '/../../data';

    // Initialize storage
    $storage = new HoneypotJsonStorage($dataDir);

    // Add message to storage
    $result = $storage->addMessage($username, $message);

    // Return response
    if ($result['success']) {
        http_response_code(201); // Created
        $response = $result;
    } else {
        http_response_code(400); // Bad Request
        $response = $result;
    }

} catch (Exception $e) {
    http_response_code(500); // Server error
    $response = [
        'success' => false,
        'message' => 'Server error: ' . $e->getMessage()
    ];
}

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
