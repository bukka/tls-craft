<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\PreSharedKey;

Logger::enable();

$hostname = 'localhost';
$port = 4433;

// Define a shared PSK (must match server)
$pskIdentity = 'my-test-psk';
$pskKey = hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
$cipherSuite = CipherSuite::TLS_AES_128_GCM_SHA256;

echo "=== 0-RTT Test with External PSK ===\n\n";

// Create PSK with early data support
$psk = PreSharedKey::external(
    $pskIdentity,
    $pskKey,
    $cipherSuite,
);

echo "PSK Identity: $pskIdentity\n";
echo 'PSK Key: '.bin2hex($pskKey)."\n";

// Define early data to send
$earlyData = "GET / HTTP/1.1\r\nHost: $hostname\r\n\r\n";

echo 'Early Data: '.json_encode($earlyData)."\n\n";

// Create client with external PSK and early data
$client = AppFactory::createClient(
    hostname: $hostname,
    port: $port,
    externalPsks: [$psk],
    earlyData: $earlyData,
    onEarlyDataRejected: function (?string $earlyData) {
        echo 'Early Data rejected: '.$earlyData."\n\n";
    },
    debug: true,
);

try {
    echo "Connecting with 0-RTT early data...\n\n";

    $session = $client->connect();

    echo "\n✓ Connection established!\n";
    echo 'Early data accepted: '.($session->isEarlyDataAccepted() ? 'YES' : 'NO')."\n\n";

    // Send follow-up data
    $message = "follow-up message\n";
    echo "Sending follow-up: $message\n";
    $session->send($message);

    $session->close();
    echo "Connection closed\n";

} catch (Exception $e) {
    echo 'Error: '.$e->getMessage()."\n";
    echo $e->getTraceAsString()."\n";
}
