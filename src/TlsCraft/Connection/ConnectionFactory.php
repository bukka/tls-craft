<?php

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\State\Manager;

class ConnectionFactory
{
    public static function createControlledClient(
        string $hostname,
        int $port,
        ?FlowController $controller = null
    ): Client {
        return new Client($hostname, $port, $controller);
    }

    public static function createControlledServer(
        string $certPath,
        string $keyPath,
        ?FlowController $controller = null
    ): Server {
        return new Server($certPath, $keyPath, $controller);
    }
}