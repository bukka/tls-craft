<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Session\PreSharedKey;

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

// Define the same PSK as client
$pskIdentity = 'my-test-psk';
$pskKey = hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'); // matching the Makefile key
$cipherSuite = CipherSuite::TLS_AES_128_GCM_SHA256;

echo "PSK Test Server\n";
echo "===============\n";
echo "PSK Identity: $pskIdentity\n";
echo 'PSK Key: '.bin2hex($pskKey)."\n";
echo "Cipher Suite: {$cipherSuite->name}\n\n";

// Create PSK object
$psk = PreSharedKey::external($pskIdentity, $pskKey, $cipherSuite);

$server = AppFactory::createServer(
    certificatePath: $certFile,
    privateKeyPath: $keyFile,
    debug: true,
);

echo "Starting TLS 1.3 server on 0.0.0.0:$port\n";
echo "PSK authentication: ENABLED\n";
echo "Waiting for connections...\n\n";

$server->listen('0.0.0.0', $port);

while (true) {
    try {
        echo "Waiting for client connection...\n";
        $session = $server->accept();

        echo "Client connected!\n";

        // Check if PSK was used
        $context = $session->getOrchestrator()->getContext();
        if ($context->hasPsk()) {
            echo "✓ PSK authentication used\n";
            $selectedPsk = $context->getSelectedPsk();
            if ($selectedPsk) {
                echo '  Identity: '.$selectedPsk->identity."\n";
            }
        } else {
            echo "✓ Certificate authentication used\n";
        }

        // Receive data
        $data = $session->receive(1024);
        echo 'Received: '.$data."\n";

        // Send response (echo back)
        $session->send($data);
        echo "Sent (echo): $data\n";

        $session->close();
        echo "Session closed\n\n";

    } catch (Exception $e) {
        echo 'Error: '.$e->getMessage()."\n";
        echo $e->getTraceAsString()."\n\n";
    }
}
