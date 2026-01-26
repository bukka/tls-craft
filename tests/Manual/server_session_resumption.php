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

echo "=== Session Resumption Test Server (No Early Data) ===\n\n";
echo "Certificate: $certFile\n";
echo "Starting TLS 1.3 server on 0.0.0.0:$port\n";
echo "Session resumption: ENABLED\n";
echo "Early data: DISABLED\n";
echo "Waiting for connections...\n\n";

$server->listen('0.0.0.0', $port);

$connectionCount = 0;

while (true) {
    try {
        echo "Waiting for client connection...\n";
        $session = $server->accept();

        $connectionCount++;
        $context = $session->getOrchestrator()->getContext();

        if ($context->isResuming()) {
            echo "✓ Client connected! (Connection #$connectionCount)\n";
            echo "✓ Session RESUMED via PSK\n";
        } else {
            echo "✓ Client connected! (Connection #$connectionCount)\n";
            echo "✓ Full handshake completed\n";
            echo "  Session ticket will be sent for future resumption\n";
        }

        // Receive data
        $data = $session->receive(1024);
        if ($data !== null && $data !== '') {
            echo "Received: " . trim($data) . "\n";

            // Send HTTP response
            $response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            $session->send($response);
            echo "Sent: HTTP/1.1 200 OK\n";
        }

        $session->close();
        echo "Session closed\n\n";

    } catch (Exception $e) {
        echo 'Error: '.$e->getMessage()."\n";
        echo $e->getTraceAsString()."\n\n";
    }
}
