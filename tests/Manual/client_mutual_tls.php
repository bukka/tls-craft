<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;

Logger::enable();

$type = $argv[1] ?? 'ec';
$certFile = __DIR__."/certs/client_$type.crt";
$keyFile = __DIR__."/certs/client_$type.key";

$client = AppFactory::createClient('localhost', 4433, $certFile, $keyFile, debug: true);
$session = $client->connect(30000);

$session->send('ctest');
var_dump($session->receive(5));

$session->close();
