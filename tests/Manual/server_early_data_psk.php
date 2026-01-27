<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Protocol\EarlyDataServerMode;
use Php\TlsCraft\Session\PreSharedKey;

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

// Define the same PSK as client
$pskIdentity = 'my-test-psk';
$pskKey = hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
$cipherSuite = CipherSuite::TLS_AES_128_GCM_SHA256;
$maxEarlyDataSize = 16384;

echo "=== 0-RTT Server with External PSK ===\n\n";
echo "PSK Identity: $pskIdentity\n";
echo 'PSK Key: '.bin2hex($pskKey)."\n";
echo "Cipher Suite: {$cipherSuite->name}\n";
echo "Max Early Data: $maxEarlyDataSize bytes\n";
echo "Early Data Mode: ACCEPT\n\n";

// Create PSK object
$psk = PreSharedKey::external($pskIdentity, $pskKey, $cipherSuite, $maxEarlyDataSize);

$server = AppFactory::createServer(
    certificatePath: $certFile,
    privateKeyPath: $keyFile,
    externalPsks: [$psk],
    maxEarlyDataSize: $maxEarlyDataSize,
    earlyDataServerMode: EarlyDataServerMode::ACCEPT,
    debug: true,
);

echo "Starting TLS 1.3 server on 0.0.0.0:$port\n";
echo "Waiting for connections...\n\n";

$server->listen('0.0.0.0', $port);

while (true) {
    try {
        echo "Waiting for client connection...\n";
        $session = $server->accept();

        echo "✓ Client connected!\n";

        // Check if PSK was used
        $context = $session->getOrchestrator()->getContext();
        if ($context->hasPsk()) {
            echo "✓ PSK authentication used\n";
            $selectedPsk = $context->getSelectedPsk();
            if ($selectedPsk) {
                echo "  Identity: {$selectedPsk->identity}\n";
            }
        } else {
            echo "✓ Certificate authentication used\n";
        }

        // Check for early data (0-RTT)
        $earlyData = $context->getReceivedEarlyData();
        if ($earlyData !== null) {
            echo "✓ Early data received (0-RTT)!\n";
            echo '  Size: '.strlen($earlyData)." bytes\n";
            echo "  Content: $earlyData\n";
        } else {
            echo "  No early data received\n";
        }

        // Receive regular data (if any)
        $data = $session->receive(1024);
        if ($data) {
            echo "Received (regular): $data\n";

            // Send response
            $response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            $session->send($response);
            echo "Sent: $response\n";
        }

        $session->close();
        echo "Session closed\n\n";

    } catch (Exception $e) {
        echo 'Error: '.$e->getMessage()."\n";
        echo $e->getTraceAsString()."\n\n";
    }
}
