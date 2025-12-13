<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\ConnectionFactory;

final class AppFactory
{
    public static function createClient(
        string $hostname,
        int $port,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Client {
        RuntimeEnvironment::assertOpenSsl3();

        // You can still pass config/factory through; Client will build from them.
        return new Client($hostname, $port, $config, $connectionFactory, debug: $debug);
    }

    public static function createServer(
        string $certificatePath,
        string $privateKeyPath,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
    ): Server {
        RuntimeEnvironment::assertOpenSsl3();

        return new Server($certificatePath, $privateKeyPath, $config, $connectionFactory);
    }
}
