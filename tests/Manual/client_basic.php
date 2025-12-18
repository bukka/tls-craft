<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;

Logger::enable();

$client = AppFactory::createClient('localhost', 4433, debug: true);
$session = $client->connect(30000);

$session->send("test\n");
var_dump($session->receive(5));

$session->close();
