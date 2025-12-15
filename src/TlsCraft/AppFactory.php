<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\ConnectionFactory;

final class AppFactory
{
    public static function createClient(
        string $hostname,
        int $port,
        ?string $certificatePath = null,
        ?string $privateKeyPath = null,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Client {
        RuntimeEnvironment::assertOpenSsl3();
        if ($certificatePath && $privateKeyPath) {
            $config = ($config ?? new Config())->withCertificate($certificatePath, $privateKeyPath);
        }
        // You can still pass config/factory through; Client will build from them.
        return new Client($hostname, $port, $config, $connectionFactory, debug: $debug);
    }

    public static function createServer(
        string $certificatePath,
        string $privateKeyPath,
        bool $mutualTls = false,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
    ): Server {
        RuntimeEnvironment::assertOpenSsl3();
        if ($config === null) {
            $config = new Config();
        }
        $config->withCertificate($certificatePath, $privateKeyPath);
        return new Server($config, $connectionFactory);
    }
}
