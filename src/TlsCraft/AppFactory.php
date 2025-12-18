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

        // If no config provided, create one
        if ($config === null) {
            $config = new Config(serverName: $hostname);
        }

        // Add certificate if provided
        if ($certificatePath && $privateKeyPath) {
            $config->withCertificate($certificatePath, $privateKeyPath);
        }

        return new Client($hostname, $port, $config, $connectionFactory, debug: $debug);
    }

    public static function createServer(
        string $certificatePath,
        string $privateKeyPath,
        bool $mutualTls = false,
        ?string $clientCaFile = null,
        ?string $clientCaPath = null,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Server {
        RuntimeEnvironment::assertOpenSsl3();

        if ($config === null) {
            $config = new Config();
        }

        $config->withCertificate($certificatePath, $privateKeyPath);

        if ($mutualTls) {
            $config->setRequestClientCertificate(true);
            $config->withCustomCa($clientCaPath, $clientCaFile);
        }

        return new Server($config, $connectionFactory, debug: $debug);
    }
}
