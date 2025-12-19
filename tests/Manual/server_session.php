<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\PlainSessionTicketSerializer;
use Php\TlsCraft\Session\Storage\InMemorySessionStorage;

Logger::enable();

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

$server = AppFactory::createServer(
    certificatePath: $certFile,
    privateKeyPath: $keyFile,
    sessionStorage: new InMemorySessionStorage(),
    sessionTicketSerializer: new PlainSessionTicketSerializer(),
    sessionLifetime: 7200,
    debug: true,
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
            echo "✓ Session RESUMED (PSK used)\n";
        } else {
            echo "✓ Full handshake completed\n";
        }

        // Receive data
        $data = $session->receive(1024);
        echo 'Received: '.var_export($data, true)."\n";

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
