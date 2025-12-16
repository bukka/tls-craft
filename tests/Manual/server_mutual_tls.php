<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;

Logger::enable();

$type = 'ec';
$certFile = __DIR__."/certs/client_$type.crt";
$keyFile = __DIR__."/certs/client_$type.key";
$caFile = __DIR__."/certs/ca_$type.crt";
$port = 4433;

$server = AppFactory::createServer($certFile, $keyFile, true, $caFile);
$server->listen('0.0.0.0', $port);

$session = $server->accept();

var_dump($session->receive(5));
$session->send('stest');

$session->close();
