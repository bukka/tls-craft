<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;

class Session
{
    private string $receiveBuffer = '';

    public function __construct(
        private Connection $connection,
        private ProtocolOrchestrator $orchestrator,
    ) {
    }

    public function send(string $data): void
    {
        $this->orchestrator->sendApplicationData($data);
    }

    /**
     * Receive application data up to $maxLength bytes.
     * Returns null if connection is closed or no data available.
     * May return less than $maxLength bytes if that's all that's available.
     */
    public function receive(int $maxLength = 8192): ?string
    {
        // First, check if we have buffered data
        if ($this->receiveBuffer !== '') {
            $result = substr($this->receiveBuffer, 0, $maxLength);
            $this->receiveBuffer = substr($this->receiveBuffer, strlen($result));

            return $result;
        }

        // No buffered data - try to receive more
        $data = $this->orchestrator->receiveApplicationData();

        if ($data === null) {
            return null; // No data available or connection closed
        }

        // If we got more than requested, buffer the rest
        if (strlen($data) > $maxLength) {
            $result = substr($data, 0, $maxLength);
            $this->receiveBuffer = substr($data, $maxLength);

            return $result;
        }

        return $data;
    }

    /**
     * Check if there's buffered data available without blocking.
     */
    public function hasBufferedData(): bool
    {
        return $this->receiveBuffer !== '';
    }

    /**
     * Get the amount of buffered data.
     */
    public function getBufferedLength(): int
    {
        return strlen($this->receiveBuffer);
    }

    /**
     * Clear the receive buffer (useful for testing or error recovery).
     */
    public function clearBuffer(): void
    {
        $this->receiveBuffer = '';
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

    public function getState(): State\ConnectionState
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

    public function getContext(): Context
    {
        return $this->orchestrator->getContext();
    }
}
