<?php

namespace Php\TlsCraft\Connection;

class StreamHandle implements Handle
{

    private $resource;
    private bool $isServer;

    public function __construct($resource, bool $isServer = false)
    {
        $this->resource = $resource;
        $this->isServer = $isServer;
    }

    public function read(int $length): string
    {
        if ($length <= 0) {
            throw new CraftException("Invalid read length: {$length}");
        }

        if (!$this->isConnected()) {
            throw new CraftException("Cannot read from closed connection");
        }

        $data = fread($this->resource, $length);

        if ($data === false) {
            throw new CraftException("Failed to read from connection");
        }

        return $data;
    }

    public function write(string $data): int
    {
        if (empty($data)) {
            return 0;
        }

        if (!$this->isConnected()) {
            throw new CraftException("Cannot write to closed connection");
        }

        $result = fwrite($this->resource, $data);

        if ($result === false) {
            throw new CraftException("Failed to write to connection");
        }

        return $result;
    }

    public function accept(?float $timeout = null): Handle
    {
        if (!$this->isServer) {
            throw new CraftException("Cannot accept on client connection");
        }

        $clientResource = stream_socket_accept($this->resource, $timeout);

        if (!$clientResource) {
            throw new CraftException("Failed to accept connection");
        }

        // Set optimal options for client connection
        stream_set_blocking($clientResource, true);

        return new self($clientResource, false);
    }

    public function isConnected(): bool
    {
        return is_resource($this->resource) && !feof($this->resource);
    }

    public function close(): void
    {
        if (is_resource($this->resource)) {
            fclose($this->resource);
        }
    }

    public function getLocalName(): string
    {
        if (!$this->isConnected()) {
            return '';
        }

        $name = stream_socket_get_name($this->resource, false);
        return $name !== false ? $name : '';
    }

    public function getPeerName(): string
    {
        if (!$this->isConnected()) {
            return '';
        }

        $name = stream_socket_get_name($this->resource, true);
        return $name !== false ? $name : '';
    }

    public function setTimeout(float $timeout): void
    {
        if ($this->isConnected()) {
            stream_set_timeout(
                $this->resource,
                (int)$timeout,
                (int)(($timeout - floor($timeout)) * 1000000)
            );
        }
    }

    public function setBlocking(bool $blocking): void
    {
        if ($this->isConnected()) {
            stream_set_blocking($this->resource, $blocking);
        }
    }

    public function select(array $otherHandles, float $timeout, bool $checkWrite): array
    {
        if (!$this->isConnected()) {
            return ['read' => [], 'write' => [], 'ready_count' => 0];
        }

        // Build resource arrays
        $readResources = [$this->resource];
        $writeResources = $checkWrite ? [$this->resource] : [];

        // Add other handles
        foreach ($otherHandles as $handle) {
            if ($handle->isConnected()) {
                $readResources[] = $handle->getResource();
                if ($checkWrite) {
                    $writeResources[] = $handle->getResource();
                }
            }
        }

        $except = null;
        $result = stream_select(
            $readResources,
            $writeResources,
            $except,
            (int)$timeout,
            (int)(($timeout - floor($timeout)) * 1000000)
        );

        if ($result === false) {
            throw new CraftException("Failed to select on streams");
        }

        // Map back to handles
        $readReady = [];
        $writeReady = [];

        if (in_array($this->resource, $readResources)) {
            $readReady[] = $this;
        }
        if (in_array($this->resource, $writeResources)) {
            $writeReady[] = $this;
        }

        foreach ($otherHandles as $handle) {
            if (in_array($handle->getResource(), $readResources)) {
                $readReady[] = $handle;
            }
            if (in_array($handle->getResource(), $writeResources)) {
                $writeReady[] = $handle;
            }
        }

        return [
            'read' => $readReady,
            'write' => $writeReady,
            'ready_count' => $result
        ];
    }

    public function getResource(): mixed
    {
        return $this->resource;
    }
}