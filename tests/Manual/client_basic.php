<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Php\TlsCraft\Client;

$client = new Client('localhost', 4433);
$conn = $client->connect()->getConnection();

$conn->write("ctest");
var_dump($conn->read(5));

$conn->close();
