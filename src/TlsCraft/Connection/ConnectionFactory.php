<?php

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Exceptions\CraftException;

/**
 * Connection factory for creating handles
 */
class ConnectionFactory
{
    /**
     * Create client connection handle
     */
    public static function connect(
        string $address,
        int    $port,
        float  $timeout = 30.0,
        array  $options = []
    ): Handle
    {
        $defaultOptions = [
            'tcp_nodelay' => true,
            'so_reuseport' => true,
        ];

        $streamOptions = array_merge($defaultOptions, $options);
        $context = stream_context_create(['socket' => $streamOptions]);

        $resource = stream_socket_client(
            "tcp://{$address}:{$port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$resource) {
            throw new CraftException("Failed to connect to {$address}:{$port}: {$errstr} (errno: {$errno})");
        }

        // Set optimal socket options
        stream_set_blocking($resource, true);
        stream_set_timeout($resource, (int)$timeout, (int)(($timeout - floor($timeout)) * 1000000));

        return new StreamHandle($resource, false);
    }

    /**
     * Create server connection handle
     */
    public static function server(
        string $address,
        int    $port,
        array  $options = []
    ): Handle
    {
        $resource = stream_socket_server(
            "tcp://{$address}:{$port}",
            $errno,
            $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN
        );

        if (!$resource) {
            throw new CraftException("Failed to bind to {$address}:{$port}: {$errstr} (errno: {$errno})");
        }

        return new StreamHandle($resource, true);
    }

    /**
     * Create a pair of connected handles for testing
     */
    public static function createSocketPair(): array
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        if ($sockets === false) {
            throw new CraftException("Failed to create socket pair");
        }

        return [
            new StreamHandle($sockets[0], false),
            new StreamHandle($sockets[1], false)
        ];
    }
}
