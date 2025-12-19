<?php

namespace Php\TlsCraft;

use InvalidArgumentException;
use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Session\SessionStorage;
use Php\TlsCraft\Session\SessionTicketSerializer;

final class AppFactory
{
    /**
     * Create a TLS 1.3 client
     *
     * @param string                       $hostname                Server hostname (used for SNI and session cache key)
     * @param int                          $port                    Server port number
     * @param string|null                  $certificatePath         Path to client certificate file (PEM format, for mutual TLS)
     * @param string|null                  $privateKeyPath          Path to client private key file (PEM format, for mutual TLS)
     * @param SessionStorage|null          $sessionStorage          Storage backend for session tickets (enables resumption if provided)
     * @param SessionTicketSerializer|null $sessionTicketSerializer Serializer for tickets (null = opaque tickets, recommended for clients)
     * @param int                          $sessionLifetime         Session ticket lifetime in seconds (default: 86400 = 24 hours)
     * @param Config|null                  $config                  Custom configuration object (if provided, overrides individual parameters)
     * @param ConnectionFactory|null       $connectionFactory       Custom connection factory for advanced use cases
     * @param bool                         $debug                   Enable debug logging
     *
     * @return Client Configured TLS client
     */
    public static function createClient(
        string $hostname,
        int $port,
        ?string $certificatePath = null,
        ?string $privateKeyPath = null,
        ?SessionStorage $sessionStorage = null,
        ?SessionTicketSerializer $sessionTicketSerializer = null,
        int $sessionLifetime = 86400,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Client {
        RuntimeEnvironment::assertOpenSsl3();

        // If no config provided, create one
        if ($config === null) {
            $config = new Config(serverName: $hostname);
        }

        // Add certificate if provided (for mutual TLS)
        if ($certificatePath && $privateKeyPath) {
            $config = $config->withCertificate($certificatePath, $privateKeyPath);
        }

        // Configure session resumption if storage provided
        if ($sessionStorage !== null) {
            $config = $config->withSessionResumption($sessionStorage, $sessionLifetime);
        }

        // Configure ticket serializer if provided
        if ($sessionTicketSerializer !== null) {
            $config = $config->withSessionTicketSerializer($sessionTicketSerializer);
        }

        return new Client($hostname, $port, $config, $connectionFactory, debug: $debug);
    }

    /**
     * Create a TLS 1.3 server
     *
     * @param string                       $certificatePath         Path to server certificate file (PEM format)
     * @param string                       $privateKeyPath          Path to server private key file (PEM format)
     * @param bool                         $mutualTls               Require client certificate authentication
     * @param string|null                  $clientCaFile            Path to CA bundle file for verifying client certificates
     * @param string|null                  $clientCaPath            Path to directory containing CA certificates for verifying client certificates
     * @param SessionStorage|null          $sessionStorage          Storage backend for session tickets (enables resumption if provided)
     * @param SessionTicketSerializer|null $sessionTicketSerializer Serializer for tickets (REQUIRED if sessionStorage provided)
     * @param int                          $sessionLifetime         Session ticket lifetime in seconds (default: 86400 = 24 hours)
     * @param Config|null                  $config                  Custom configuration object (if provided, overrides individual parameters)
     * @param ConnectionFactory|null       $connectionFactory       Custom connection factory for advanced use cases
     * @param bool                         $debug                   Enable debug logging
     *
     * @return Server Configured TLS server
     *
     * @throws InvalidArgumentException If session resumption is enabled without a serializer
     */
    public static function createServer(
        string $certificatePath,
        string $privateKeyPath,
        bool $mutualTls = false,
        ?string $clientCaFile = null,
        ?string $clientCaPath = null,
        ?SessionStorage $sessionStorage = null,
        ?SessionTicketSerializer $sessionTicketSerializer = null,
        int $sessionLifetime = 86400,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Server {
        RuntimeEnvironment::assertOpenSsl3();

        if ($config === null) {
            $config = new Config();
        }

        $config = $config->withCertificate($certificatePath, $privateKeyPath);

        if ($mutualTls) {
            $config = $config->setRequestClientCertificate(true)
                ->withCustomCa($clientCaPath, $clientCaFile);
        }

        // Configure session resumption if storage provided
        if ($sessionStorage !== null) {
            $config = $config->withSessionResumption($sessionStorage, $sessionLifetime);

            // Server MUST have a serializer to encrypt tickets
            if ($sessionTicketSerializer === null) {
                throw new InvalidArgumentException('Server with session resumption requires a SessionTicketSerializer. Use PlainSessionTicketSerializer for testing or EncryptedSessionTicketSerializer for production.');
            }

            $config = $config->withSessionTicketSerializer($sessionTicketSerializer);
        }

        return new Server($config, $connectionFactory, debug: $debug);
    }
}
