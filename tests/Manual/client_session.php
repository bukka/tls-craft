<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Session\Storage\FileSessionStorage;

$hostname = 'localhost';
$port = 4433;
$sessionsDir = __DIR__.'/certs/sessions';

// Clean up old session tickets before starting
echo "Cleaning up old session tickets...\n";
if (is_dir($sessionsDir)) {
    $files = glob($sessionsDir.'/*');
    foreach ($files as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    echo 'Removed '.count($files)." old session file(s)\n";
} else {
    mkdir($sessionsDir, 0755, true);
    echo "Created sessions directory\n";
}

echo "\nConnecting to $hostname:$port\n";
echo "Session resumption: ENABLED\n\n";

// First connection
echo "=== FIRST CONNECTION ===\n";
try {
    $client = AppFactory::createClient(
        hostname: $hostname,
        port: $port,
        sessionStorage: new FileSessionStorage($sessionsDir),
        sessionLifetime: 7200,
        debug: true,
    );

    $session = $client->connect();

    $context = $session->getOrchestrator()->getContext();
    if ($context->isResuming()) {
        echo "✓ Session RESUMED (PSK used)\n";
    } else {
        echo "✓ Full handshake completed\n";
    }

    $message = "test\n";
    $session->send($message);
    echo "Sent: $message";

    echo 'Read: '.$session->receive(1024)."\n";

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
        sessionStorage: new FileSessionStorage($sessionsDir),
        sessionLifetime: 7200,
        debug: true,
    );

    $session = $client->connect();

    $context = $session->getOrchestrator()->getContext();
    if ($context->isResuming()) {
        echo "✓ Session RESUMED (PSK used) ✓✓✓\n";
    } else {
        echo "✗ Full handshake (resumption failed)\n";
    }

    $message = "client-test-resumed\n";
    $session->send($message);
    echo "Sent: $message";

    echo 'Read: '.$session->receive(1024)."\n";

    $session->close();
    echo "Connection closed\n";

} catch (Exception $e) {
    echo 'Error: '.$e->getMessage()."\n";
    echo $e->getTraceAsString()."\n";
    exit(1);
}

echo "\n=== TEST COMPLETED ===\n";
