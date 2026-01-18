<?php

require_once __DIR__.'/../../vendor/autoload.php';

use Php\TlsCraft\AppFactory;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\Storage\InMemorySessionStorage;

Logger::enable();

$hostname = 'localhost';
$port = 4433;

$sessionStorage = new InMemorySessionStorage();

// Step 1: Initial connection to get session ticket
echo "=== Step 1: Get session ticket ===\n\n";

$client1 = AppFactory::createClient(
    hostname: $hostname,
    port: $port,
    sessionStorage: $sessionStorage,
    debug: true,
);

$session1 = $client1->connect();
$session1->send("hello\n");
$session1->close();

$tickets = $sessionStorage->retrieve($hostname);
echo "\nTicket max_early_data_size: ".$tickets[0]->getMaxEarlyDataSize()."\n\n";

sleep(1);

// Step 2: Resumption with early data
echo "=== Step 2: Resumption with early data ===\n\n";

$earlyData = "GET / HTTP/1.1\r\nHost: $hostname\r\n\r\n";

$client2 = AppFactory::createClient(
    hostname: $hostname,
    port: $port,
    sessionStorage: $sessionStorage,
    earlyData: $earlyData,
    debug: true,
);

$session2 = $client2->connect();

echo "\nEarly data accepted: ".($session2->isEarlyDataAccepted() ? 'yes' : 'no')."\n";

$session2->send("follow-up\n");
$session2->close();
