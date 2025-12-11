<?php

require_once __DIR__ . '/openssl_server.inc';

// Configuration matching your OpenSSL s_server setup
$certFile = __DIR__ . '/certs/server_rsa.crt';
$keyFile = __DIR__ . '/certs/server_rsa.key';
$port = 4433;

openssl_server_start($certFile, $keyFile, $port);
