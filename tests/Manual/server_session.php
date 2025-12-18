<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Config;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\Storage\InMemorySessionStorage;

Logger::enable();

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

// Create config with session resumption enabled
$config = (new Config())
    ->withCertificate($certFile, $keyFile)
    ->withSessionResumption(
        storage: new InMemorySessionStorage(),
        lifetimeSeconds: 7200, // 2 hours
    );

$server = AppFactory::createServer(
    certificatePath: $certFile,
    privateKeyPath: $keyFile,
    config: $config,
);

echo "Starting TLS 1.3 server on 0.0.0.0:$port\n";
echo "Session resumption: ENABLED\n";
echo "Waiting for connections...\n\n";

$server->listen('0.0.0.0', $port);

while (true) {
    try {
        echo "Waiting for client connection...\n";
        $session = $server->accept();

        echo "Client connected!\n";

        // Check if session was resumed
        $context = $session->getOrchestrator()->getContext();
        if ($context->isResuming()) {
            echo "Session RESUMED (PSK used)\n";
        } else {
            echo "Full handshake completed\n";
        }

        // Receive data
        $data = $session->receive(1024);
        echo 'Received: '.var_export($data, true)."\n";

        // Send response
        $response = 'server-response-'.time();
        $session->send($response);
        echo "Sent: $response\n";

        $session->close();
        echo "Session closed\n\n";

    } catch (Exception $e) {
        echo 'Error: '.$e->getMessage()."\n";
        echo $e->getTraceAsString()."\n\n";
    }
}
