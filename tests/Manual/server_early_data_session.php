<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Protocol\EarlyDataServerMode;
use Php\TlsCraft\Session\PlainSessionTicketSerializer;
use Php\TlsCraft\Session\Storage\InMemorySessionStorage;

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

echo "=== 0-RTT Server with Session Resumption ===\n\n";
echo "Certificate: $certFile\n";
echo "Max Early Data: 16384 bytes\n";
echo "Early Data Mode: ACCEPT\n\n";

$server = AppFactory::createServer(
    certificatePath: $certFile,
    privateKeyPath: $keyFile,
    sessionStorage: new InMemorySessionStorage(),
    sessionTicketSerializer: new PlainSessionTicketSerializer(),
    sessionLifetime: 7200,
    maxEarlyDataSize: 16384,
    earlyDataServerMode: EarlyDataServerMode::ACCEPT,
    debug: true,
);

echo "Starting TLS 1.3 server on 0.0.0.0:$port\n";
echo "Session resumption: ENABLED\n";
echo "Waiting for connections...\n\n";

$server->listen('0.0.0.0', $port);

$connectionCount = 0;

while (true) {
    try {
        echo "Waiting for client connection...\n";
        $session = $server->accept();
        $connectionCount++;

        echo "✓ Client connected! (Connection #$connectionCount)\n";

        // Check if session was resumed
        $context = $session->getOrchestrator()->getContext();
        if ($context->isResuming()) {
            echo "✓ Session RESUMED (PSK used)\n";

            // Check for early data (0-RTT)
            $earlyData = $context->getReceivedEarlyData();
            if ($earlyData !== null) {
                echo "✓ Early data received (0-RTT)!\n";
                echo "  Size: ".strlen($earlyData)." bytes\n";
                echo "  Content: $earlyData\n";
            } else {
                echo "  No early data received\n";
            }
        } else {
            echo "✓ Full handshake completed\n";
            echo "  Session ticket will be sent for future resumption\n";
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
