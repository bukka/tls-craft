<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;

Logger::enable();

$client = AppFactory::createClient('localhost', 4433);
$conn = $client->connect()->getConnection();

$conn->write("ctest");
var_dump($conn->read(5));

$conn->close();
