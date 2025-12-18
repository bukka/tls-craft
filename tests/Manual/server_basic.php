<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;

Logger::enable();

$certFile = __DIR__.'/certs/server_ec.crt';
$keyFile = __DIR__.'/certs/server_ec.key';
$port = 4433;

$server = AppFactory::createServer($certFile, $keyFile);
$server->listen('0.0.0.0', $port);

$session = $server->accept();

var_dump($session->receive(5));
$session->send('stest');

$session->close();
