<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;

class Session
{
    public function __construct(
        private Connection $connection,
        private ProtocolOrchestrator $orchestrator
    ) {}

    public function send(string $data): void
    {
        $this->orchestrator->sendApplicationData($data);
    }

    public function receive(int $maxLength = 8192): ?string
    {
        $data = $this->orchestrator->receiveApplicationData();
        return $data ? substr($data, 0, $maxLength) : null;
    }

    public function sendKeyUpdate(bool $requestUpdate = false): void
    {
        $this->orchestrator->sendKeyUpdate($requestUpdate);
    }

    public function sendAlert(AlertLevel $level, AlertDescription $description): void
    {
        $this->orchestrator->sendAlert($level, $description);
    }

    public function close(): void
    {
        $this->orchestrator->close();
        $this->connection->close();
    }

    public function abruptClose(): void
    {
        $this->orchestrator->abruptClose();
        $this->connection->close();
    }

    public function isConnected(): bool
    {
        return $this->orchestrator->isConnected();
    }

    public function getState(): \Php\TlsCraft\State\ConnectionState
    {
        return $this->orchestrator->getStateTracker()->getConnectionState();
    }

    public function getConnection(): Connection
    {
        return $this->connection;
    }

    public function getOrchestrator(): ProtocolOrchestrator
    {
        return $this->orchestrator;
    }
}