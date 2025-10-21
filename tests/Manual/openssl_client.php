<?php

// Create SSL context
$context = stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
        'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER
    ]
]);

// Create server socket
$client = stream_socket_client(
    "tlsv1.3://0.0.0.0:$port",
    $errno,
    $errstr,
    300000
);

fwrite($client, "ctest");
var_dump(fread($client, 5));
