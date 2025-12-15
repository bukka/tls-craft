<?php

function openssl_server_start($certFile, $keyFile, $port)
{
    // Verify certificate files exist
    if (!file_exists($certFile) || !file_exists($keyFile)) {
        exit("Error: Certificate or key file not found!\n");
    }

    // Create SSL context
    $context = stream_context_create([
        'ssl' => [
            'local_cert' => $certFile,
            'local_pk' => $keyFile,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'crypto_method' => \STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
        ],
    ]);

    // Create server socket
    $socket = stream_socket_server(
        "tlsv1.3://0.0.0.0:$port",
        $errno,
        $errstr,
        \STREAM_SERVER_BIND | \STREAM_SERVER_LISTEN,
        $context,
    );

    if (!$socket) {
        exit("Error creating server: $errstr ($errno)\n");
    }

    echo "TLS 1.3 Server listening on port $port...\n";
    echo "Waiting for connections...\n\n";

    while (true) {
        // Accept client connection
        $client = stream_socket_accept($socket, -1, $peerName);

        if (!$client) {
            continue;
        }

        echo "TLS handshake successful!\n";

        // Get connection info
        $cryptoInfo = stream_get_meta_data($client);
        if (isset($cryptoInfo['crypto'])) {
            echo 'Protocol: '.($cryptoInfo['crypto']['protocol'] ?? 'unknown')."\n";
            echo 'Cipher: '.($cryptoInfo['crypto']['cipher_name'] ?? 'unknown')."\n";
        }
        echo "\n";

        // Read data from client
        $data = fread($client, 8192);

        if ($data !== false && $data !== '') {
            echo 'Received '.strlen($data)." bytes from client:\n";
            echo 'Data (string): '.$data."\n";
            echo 'Data (hex): '.bin2hex($data)."\n\n";

            // Echo back "stest" (similar to -rev behavior)
            $response = 'stest';
            echo "Sending response: $response\n";
            fwrite($client, $response);
            fflush($client);
        } else {
            echo "No data received or connection closed\n";
        }

        // Give client time to read response
        usleep(100000); // 100ms

        // Close connection
        fclose($client);
        echo "Connection closed\n\n";
        echo "Waiting for next connection...\n\n";
    }
}

$type = $argv[1] ?? 'ec';
$certFile = __DIR__."/certs/server_$type.crt";
$keyFile = __DIR__."/certs/server_$type.key";

openssl_server_start($certFile, $keyFile, 9443);
