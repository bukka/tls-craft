<?php

/**
 * Example: Using 0-RTT Early Data with TlsCraft
 *
 * This example demonstrates how to use TLS 1.3 early data (0-RTT)
 * for reduced latency on resumed connections.
 *
 * IMPORTANT SECURITY CONSIDERATIONS:
 * - Early data is NOT replay-protected by TLS
 * - Only use for idempotent operations (GET requests, safe queries)
 * - Never use for state-changing operations without application-level replay protection
 * - The server may reject early data at any time
 */

use Php\TlsCraft\Client;
use Php\TlsCraft\Config;
use Php\TlsCraft\Session\Storage\FileSessionStorage;

// === First Connection: Establish session and get ticket ===

$config = new Config(
    serverName: 'example.com',
);

// Enable session resumption with file-based storage
$sessionStorage = new FileSessionStorage('/tmp/tls_sessions');
$config->withSessionResumption($sessionStorage);

// Connect and perform initial handshake
$client = new Client($config);
$client->connect('example.com', 443);

// Send request and get response
$client->send("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
$response = $client->receive();

// Close connection - session ticket is now stored
$client->close();

// === Second Connection: Use early data ===

// Create new config for resumption with early data
$resumeConfig = new Config(
    serverName: 'example.com',
);

// Configure session resumption
$resumeConfig->withSessionResumption($sessionStorage);

// Configure early data
// This is the data that will be sent in 0-RTT (before handshake completes)
$earlyRequest = "GET /api/status HTTP/1.1\r\nHost: example.com\r\n\r\n";

$resumeConfig->withEarlyData(
    data: $earlyRequest,
    onRejected: function (string $rejectedData) use (&$needsResend) {
        // Server rejected early data - we need to resend after handshake
        echo "Early data rejected, will resend after handshake\n";
        $needsResend = $rejectedData;
    },
);

$needsResend = null;

// Connect with resumption and early data
$client2 = new Client($resumeConfig);
$client2->connect('example.com', 443);

// Check if early data was accepted
if ($client2->isEarlyDataAccepted()) {
    echo "Early data accepted! Response may already be available.\n";
} else {
    echo "Early data rejected or not sent.\n";
    
    // Resend the request over the regular connection
    if ($needsResend !== null) {
        $client2->send($needsResend);
    }
}

// Receive response (works for both accepted and rejected cases)
$response = $client2->receive();
echo $response;

$client2->close();

// === Alternative: Manual early data control ===

$manualConfig = new Config(
    serverName: 'example.com',
);

$manualConfig
    ->withSessionResumption($sessionStorage)
    ->setEnableEarlyData(true);

// Don't set early data in config - we'll send it manually
$client3 = new Client($manualConfig);

// Check if early data is possible before connecting
$ticket = $sessionStorage->get('example.com');
if ($ticket !== null && $ticket->getMaxEarlyDataSize() > 0) {
    // We can send early data
    $maxSize = $ticket->getMaxEarlyDataSize();
    echo "Can send up to {$maxSize} bytes of early data\n";
    
    // Set the early data
    $manualConfig->setEarlyData("GET /fast HTTP/1.1\r\nHost: example.com\r\n\r\n");
}

$client3->connect('example.com', 443);
// ... rest of communication

// === Best Practices ===

/**
 * 1. Only use early data for idempotent requests:
 *    - GET requests without side effects
 *    - Read-only database queries
 *    - Cache lookups
 *
 * 2. Never use early data for:
 *    - POST/PUT/DELETE requests
 *    - Payments or financial transactions
 *    - Any state-changing operation
 *
 * 3. Always handle rejection gracefully:
 *    - Server can reject early data for any reason
 *    - Your application must be able to resend the data
 *
 * 4. Consider the replay window:
 *    - Attackers can replay early data within a time window
 *    - Add application-level replay protection if needed
 *    - Use unique request IDs or timestamps
 *
 * 5. Size limitations:
 *    - Early data size is limited by max_early_data_size in the ticket
 *    - Typically 16KB or less
 *    - Check the limit before sending
 */
