<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Config;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\Storage\FileSessionStorage;

Logger::enable();

$hostname = 'localhost';
$port = 4433;

// Create config with session resumption
$config = (new Config(serverName: $hostname))
    ->withSessionResumption(
        storage: new FileSessionStorage(__DIR__.'/certs/sessions'),
        lifetimeSeconds: 7200,
    )
    ->withoutCertificateValidation(); // For testing with self-signed certs

echo "Connecting to $hostname:$port\n";
echo "Session resumption: ENABLED\n\n";

// First connection
echo "=== FIRST CONNECTION ===\n";
try {
    $client = AppFactory::createClient(
        hostname: $hostname,
        port: $port,
        config: $config,
        debug: false,
    );

    $session = $client->connect();

    $context = $session->getOrchestrator()->getContext();
    if ($context->isResuming()) {
        echo "Session RESUMED (PSK used)\n";
    } else {
        echo "Full handshake completed\n";
    }

    $message = 'client-test-'.time();
    $session->send($message);
    echo "Sent: $message\n";

    $response = $session->receive(1024);
    echo 'Received: '.var_export($response, true)."\n";

    $session->close();
    echo "Connection closed\n\n";

} catch (Exception $e) {
    echo 'Error: '.$e->getMessage()."\n";
    echo $e->getTraceAsString()."\n";
    exit(1);
}

// Wait a moment
sleep(1);

// Second connection (should resume)
echo "=== SECOND CONNECTION (RESUMPTION TEST) ===\n";
try {
    $client = AppFactory::createClient(
        hostname: $hostname,
        port: $port,
        config: $config,
        debug: false,
    );

    $session = $client->connect();

    $context = $session->getOrchestrator()->getContext();
    if ($context->isResuming()) {
        echo "Session RESUMED (PSK used) ✓✓✓\n";
    } else {
        echo "Full handshake (resumption failed)\n";
    }

    $message = 'client-test-resumed-'.time();
    $session->send($message);
    echo "Sent: $message\n";

    $response = $session->receive(1024);
    echo 'Received: '.var_export($response, true)."\n";

    $session->close();
    echo "Connection closed\n";

} catch (Exception $e) {
    echo 'Error: '.$e->getMessage()."\n";
    echo $e->getTraceAsString()."\n";
    exit(1);
}

echo "\n=== TEST COMPLETED ===\n";
