<?php

namespace Php\TlsCraft;

use Closure;
use InvalidArgumentException;
use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Protocol\EarlyDataServerMode;
use Php\TlsCraft\Session\PreSharedKey;
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
     * @param PreSharedKey[]|null          $externalPsks            External PSKs for authentication (alternative to certificates)
     * @param SessionStorage|null          $sessionStorage          Storage backend for session tickets (enables resumption if provided)
     * @param SessionTicketSerializer|null $sessionTicketSerializer Serializer for tickets (null = opaque tickets, recommended for clients)
     * @param int                          $sessionLifetime         Session ticket lifetime in seconds (default: 86400 = 24 hours)
     * @param string|null                  $earlyData               Early data (0-RTT) to send (requires session resumption)
     * @param Closure|null                 $onEarlyDataRejected     Callback if server rejects early data: fn(string $data): void
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
        ?array $externalPsks = null,
        ?SessionStorage $sessionStorage = null,
        ?SessionTicketSerializer $sessionTicketSerializer = null,
        int $sessionLifetime = 86400,
        ?string $earlyData = null,
        ?Closure $onEarlyDataRejected = null,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Client {
        RuntimeEnvironment::assertOpenSsl3();

        // If no config provided, create one with early data parameters
        if ($config === null) {
            $config = new Config(
                serverName: $hostname,
                enableEarlyData: $earlyData !== null,  // Enable if data provided
                earlyData: $earlyData,
            );
        }

        // Add certificate if provided (for mutual TLS)
        if ($certificatePath && $privateKeyPath) {
            $config = $config->withCertificate($certificatePath, $privateKeyPath);
        }

        // Add external PSKs if provided
        if ($externalPsks !== null) {
            $config = $config->withExternalPsks($externalPsks);
        }

        // Configure session resumption if storage provided
        if ($sessionStorage !== null) {
            $config = $config->withSessionResumption($sessionStorage, $sessionLifetime);
        }

        // Configure ticket serializer if provided
        if ($sessionTicketSerializer !== null) {
            $config = $config->withSessionTicketSerializer($sessionTicketSerializer);
        }

        // Set early data rejection callback if provided
        if ($onEarlyDataRejected !== null) {
            $config = $config->setOnEarlyDataRejected($onEarlyDataRejected);
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
     * @param PreSharedKey[]|null          $externalPsks            External PSKs for authentication (alternative to certificates)
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
        ?array $externalPsks = null,
        ?SessionStorage $sessionStorage = null,
        ?SessionTicketSerializer $sessionTicketSerializer = null,
        int $sessionLifetime = 86400,
        // Add early data parameters
        int $maxEarlyDataSize = 0,
        EarlyDataServerMode $earlyDataServerMode = EarlyDataServerMode::REJECT,
        ?Closure $earlyDataServerModeCallback = null,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        bool $debug = false,
    ): Server {
        RuntimeEnvironment::assertOpenSsl3();

        if ($config === null) {
            $config = new Config(
                maxEarlyDataSize: $maxEarlyDataSize,
                earlyDataServerMode: $earlyDataServerMode,
            );
        }

        $config = $config->withCertificate($certificatePath, $privateKeyPath);

        if ($mutualTls) {
            $config = $config->setRequestClientCertificate(true)
                ->withCustomCa($clientCaPath, $clientCaFile);
        }

        // Add external PSKs if provided
        if ($externalPsks !== null) {
            $config = $config->withExternalPsks($externalPsks);
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

        // Configure early data
        if ($maxEarlyDataSize > 0 && $earlyDataServerModeCallback !== null) {
            $config = $config->setEarlyDataServerModeCallback($earlyDataServerModeCallback);
        }

        return new Server($config, $connectionFactory, debug: $debug);
    }
}
