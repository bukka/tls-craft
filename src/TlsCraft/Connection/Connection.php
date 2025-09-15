<?php

declare(strict_types=1);

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Exceptions\CraftException;

/**
 * Pure I/O connection - no protocol knowledge
 * Handles TCP socket operations only
 */
class Connection
{
    private Handle $handle;
    private string $address;
    private int $port;
    private bool $isServer;

    private function __construct(
        Handle $handle,
        string $address,
        int    $port,
        bool   $isServer = false
    )
    {
        $this->handle = $handle;
        $this->address = $address;
        $this->port = $port;
        $this->isServer = $isServer;
    }

    /**
     * Create client connection
     */
    public static function connect(
        string $address,
        int    $port,
        float  $timeout = 30.0,
        array  $options = []
    ): self
    {
        $handle = ConnectionFactory::connect($address, $port, $timeout, $options);
        return new self($handle, $address, $port, false);
    }

    /**
     * Create server connection
     */
    public static function server(
        string $address,
        int    $port,
        array  $options = []
    ): self
    {
        $handle = ConnectionFactory::server($address, $port, $options);
        return new self($handle, $address, $port, true);
    }

    /**
     * Accept incoming connection (server only)
     */
    public function accept(?float $timeout = null): self
    {
        if (!$this->isServer) {
            throw new CraftException("Cannot accept on client connection");
        }

        $clientHandle = $this->handle->accept($timeout);
        $peerName = $clientHandle->getPeerName();

        [$clientAddress, $clientPort] = $this->parsePeerName($peerName);

        return new self($clientHandle, $clientAddress, $clientPort, false);
    }

    /**
     * Read exact number of bytes (ensures complete read)
     */
    public function read(int $length): string
    {
        if ($length <= 0) {
            throw new CraftException("Invalid read length: {$length}");
        }

        $data = '';
        $remaining = $length;

        while ($remaining > 0 && $this->isConnected()) {
            $chunk = $this->handle->read($remaining);

            if ($chunk === '') {
                throw new CraftException("Connection closed during read (expected {$remaining} more bytes)");
            }

            $data .= $chunk;
            $remaining -= strlen($chunk);
        }

        if (strlen($data) !== $length) {
            throw new CraftException("Incomplete read: expected {$length} bytes, got " . strlen($data));
        }

        return $data;
    }

    /**
     * Write all data (ensures complete write)
     */
    public function write(string $data): int
    {
        if (empty($data)) {
            return 0;
        }

        $written = 0;
        $length = strlen($data);

        while ($written < $length && $this->isConnected()) {
            $result = $this->handle->write(substr($data, $written));

            if ($result <= 0) {
                throw new CraftException("Failed to write data (wrote 0 bytes)");
            }

            $written += $result;
        }

        if ($written !== $length) {
            throw new CraftException("Incomplete write: expected {$length} bytes, wrote {$written}");
        }

        return $written;
    }

    /**
     * Read available data without blocking
     */
    public function readAvailable(int $maxLength = 8192): string
    {
        if (!$this->isConnected()) {
            return '';
        }

        // Set non-blocking mode temporarily
        $this->handle->setBlocking(false);

        try {
            $data = $this->handle->read($maxLength);
        } catch (CraftException $e) {
            $data = '';
        }

        // Restore blocking mode
        $this->handle->setBlocking(true);

        return $data;
    }

    /**
     * Check if connection is active
     */
    public function isConnected(): bool
    {
        return $this->handle->isConnected();
    }

    /**
     * Check if this is a server connection
     */
    public function isServer(): bool
    {
        return $this->isServer;
    }

    /**
     * Get connection address
     */
    public function getAddress(): string
    {
        return $this->address;
    }

    /**
     * Get connection port
     */
    public function getPort(): int
    {
        return $this->port;
    }

    /**
     * Get local socket name
     */
    public function getLocalName(): string
    {
        return $this->handle->getLocalName();
    }

    /**
     * Get peer socket name
     */
    public function getPeerName(): string
    {
        return $this->handle->getPeerName();
    }

    /**
     * Set connection timeout
     */
    public function setTimeout(float $timeout): void
    {
        $this->handle->setTimeout($timeout);
    }

    /**
     * Check if data is available for reading or writing
     */
    public function select(array $otherConnections = [], float $timeout = 0.0, bool $checkWrite = false): array
    {
        $otherHandles = array_map(fn($conn) => $conn->handle, $otherConnections);
        return $this->handle->select($otherHandles, $timeout, $checkWrite);
    }

    /**
     * Check if this connection is ready for reading
     */
    public function isReadReady(float $timeout = 0.0): bool
    {
        $result = $this->select([], $timeout, false);
        return in_array($this->handle, $result['read']);
    }

    /**
     * Check if this connection is ready for writing
     */
    public function isWriteReady(float $timeout = 0.0): bool
    {
        $result = $this->select([], $timeout, true);
        return in_array($this->handle, $result['write']);
    }

    /**
     * Get underlying resource/handle (for compatibility)
     */
    public function getResource(): mixed
    {
        return $this->handle->getResource();
    }

    /**
     * Get handle instance
     */
    public function getHandle(): Handle
    {
        return $this->handle;
    }

    /**
     * Get connection statistics
     */
    public function getStats(): array
    {
        return [
            'address' => $this->address,
            'port' => $this->port,
            'is_server' => $this->isServer,
            'is_connected' => $this->isConnected(),
            'local_name' => $this->getLocalName(),
            'peer_name' => $this->getPeerName(),
            'handle_type' => get_class($this->handle),
        ];
    }

    /**
     * Close the connection
     */
    public function close(): void
    {
        $this->handle->close();
    }

    /**
     * Destructor - ensure connection is closed
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * Create a pair of connected connections for testing
     */
    public static function createSocketPair(): array
    {
        [$handle1, $handle2] = ConnectionFactory::createSocketPair();

        return [
            new self($handle1, 'local', 0, false),
            new self($handle2, 'local', 0, false)
        ];
    }

    /**
     * Parse peer name into address and port
     */
    private function parsePeerName(string $peerName): array
    {
        if (empty($peerName)) {
            throw new CraftException("Invalid peer name");
        }

        // Handle IPv6 addresses which are wrapped in brackets
        if ($peerName[0] === '[') {
            $closeBracket = strpos($peerName, ']');
            if ($closeBracket === false) {
                throw new CraftException("Invalid IPv6 peer name: {$peerName}");
            }

            $address = substr($peerName, 1, $closeBracket - 1);
            $port = (int)substr($peerName, $closeBracket + 2);
        } else {
            // IPv4 or hostname
            $parts = explode(':', $peerName);
            $port = (int)array_pop($parts);
            $address = implode(':', $parts);
        }

        return [$address, $port];
    }
}
