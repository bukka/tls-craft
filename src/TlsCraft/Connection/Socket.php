<?php

namespace Php\TlsCraft\Connection;

class Socket
{
    private $resource;
    private string $address;
    private int $port;
    private bool $isServer;

    public function __construct($resource, string $address, int $port, bool $isServer = false)
    {
        $this->resource = $resource;
        $this->address = $address;
        $this->port = $port;
        $this->isServer = $isServer;
    }

    public static function connect(string $address, int $port, float $timeout = 30.0): self
    {
        $context = stream_context_create([
            'socket' => ['tcp_nodelay' => true]
        ]);

        $resource = stream_socket_client(
            "tcp://{$address}:{$port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$resource) {
            throw new CraftException("Failed to connect to {$address}:{$port}: {$errstr}");
        }

        return new self($resource, $address, $port, false);
    }

    public static function server(string $address, int $port): self
    {
        $resource = stream_socket_server(
            "tcp://{$address}:{$port}",
            $errno,
            $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN
        );

        if (!$resource) {
            throw new CraftException("Failed to create server on {$address}:{$port}: {$errstr}");
        }

        return new self($resource, $address, $port, true);
    }

    public function accept(float $timeout = null): self
    {
        if (!$this->isServer) {
            throw new CraftException("Cannot accept on client socket");
        }

        $clientResource = stream_socket_accept($this->resource, $timeout);
        if (!$clientResource) {
            throw new CraftException("Failed to accept connection");
        }

        $peerName = stream_socket_get_name($clientResource, true);
        [$clientAddress, $clientPort] = explode(':', $peerName);

        return new self($clientResource, $clientAddress, (int)$clientPort, false);
    }

    public function getResource()
    {
        return $this->resource;
    }

    public function getAddress(): string
    {
        return $this->address;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function getLocalName(): string
    {
        return stream_socket_get_name($this->resource, false);
    }

    public function close(): void
    {
        if (is_resource($this->resource)) {
            fclose($this->resource);
        }
    }

    public function isConnected(): bool
    {
        return is_resource($this->resource) && !feof($this->resource);
    }
}