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

    public static function createMockConnection(
        ?FlowController $controller = null,
        bool $isClient = true
    ): ControlledConnection {
        // Create a mock socket for testing
        $mockSocket = new Socket(
            fopen('php://memory', 'r+'),
            '127.0.0.1',
            12345,
            !$isClient
        );

        $stateManager = new Manager($isClient);
        return new ControlledConnection($mockSocket, $stateManager, $controller);
    }
}