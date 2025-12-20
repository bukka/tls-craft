<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\PreSharedKey;

Logger::enable();

$hostname = '127.0.0.1';
$port = 4433;

// Define a shared PSK (must match server)
$pskIdentity = 'my-test-psk';
$pskKey = hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'); // matching the Makefile key
$cipherSuite = CipherSuite::TLS_AES_128_GCM_SHA256;

echo "PSK Test Client\n";
echo "===============\n";
echo "PSK Identity: $pskIdentity\n";
echo 'PSK Key: '.bin2hex($pskKey)."\n";
echo "Cipher Suite: {$cipherSuite->name}\n\n";

// Create PSK object
$psk = PreSharedKey::external($pskIdentity, $pskKey, $cipherSuite);

// Create client with external PSK
$client = AppFactory::createClient(
    hostname: $hostname,
    port: $port,
    externalPsks: [$psk],
    debug: true,
);

try {
    echo "Connecting to server at $hostname:$port with PSK...\n\n";

    $session = $client->connect();

    echo "✓ TLS 1.3 handshake completed with PSK!\n\n";

    // Send test message
    $message = "test\n";
    echo "Sending: $message\n";
    $session->send($message);

    // Receive response
    $response = $session->receive(5);
    echo "Received: $response\n\n";

    $session->close();
    echo "Connection closed\n";

} catch (Exception $e) {
    echo 'Error: '.$e->getMessage()."\n";
    echo $e->getTraceAsString()."\n";
}
