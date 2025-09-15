<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Extensions\Providers\KeyShareExtensionProvider;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;
use Php\TlsCraft\State\ProtocolValidator;
use Php\TlsCraft\State\StateTracker;

class Server
{
    private string $certificatePath;
    private string $privateKeyPath;
    private Config $config;
    private ?Connection $serverConnection = null;

    public function __construct(
        string $certificatePath,
        string $privateKeyPath,
        ?Config $config = null
    ) {
        $this->certificatePath = $certificatePath;
        $this->privateKeyPath = $privateKeyPath;
        $this->config = $config ?? $this->createDefaultConfig();

        $this->addDefaultServerExtensions();
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    public function listen(string $address, int $port): void
    {
        $this->serverConnection = Connection::server(
            $address,
            $port,
            $this->config->connectionOptions
        );
    }

    public function accept(?float $timeout = null, ?FlowController $flowController = null): Session
    {
        if (!$this->serverConnection) {
            throw new CraftException("Server not listening");
        }

        // Accept TCP connection
        $clientConnection = $this->serverConnection->accept($timeout);

        // Create state tracker for this connection
        $stateTracker = new StateTracker(false); // isClient = false

        // Create protocol validator
        $validator = $this->config->customValidator ??
            new ProtocolValidator($this->config->allowProtocolViolations);

        // Create handshake context
        $context = new Context(false); // isClient = false
        $context->setCertificateChain($this->loadCertificateChain());
        $context->setPrivateKey($this->loadPrivateKey());

        // Set up flow controller if provided
        if ($flowController === null && $this->config->onStateChange) {
            $flowController = new FlowController($stateTracker);
            $stateTracker->onStateChange($this->config->onStateChange);
        }

        // Create protocol orchestrator
        $orchestrator = new ProtocolOrchestrator(
            $stateTracker,
            $validator,
            $context,
            $this->config,
            $clientConnection,
            $flowController
        );

        // Perform TLS handshake
        $orchestrator->performServerHandshake();

        return new Session($clientConnection, $orchestrator);
    }

    public function getAddress(): string
    {
        return $this->serverConnection ? $this->serverConnection->getLocalName() : '';
    }

    public function close(): void
    {
        $this->serverConnection?->close();
    }

    private function createDefaultConfig(): Config
    {
        return new Config();
    }

    private function addDefaultServerExtensions(): void
    {
        // Add key share extension for server
        if (!$this->hasExtension(51)) {
            $this->config->serverHelloExtensions->add(
                new KeyShareExtensionProvider($this->config->supportedGroups)
            );
        }
    }

    private function hasExtension(int $type): bool
    {
        foreach ($this->config->serverHelloExtensions->getProviders() as $provider) {
            if ($provider->getExtensionType() === $type) {
                return true;
            }
        }
        return false;
    }

    private function loadCertificateChain(): array
    {
        if (!file_exists($this->certificatePath)) {
            throw new CraftException("Certificate file not found: {$this->certificatePath}");
        }

        $certData = file_get_contents($this->certificatePath);
        if ($certData === false) {
            throw new CraftException("Failed to read certificate file");
        }

        // Convert PEM to DER if needed
        if (strpos($certData, '-----BEGIN CERTIFICATE-----') !== false) {
            $cert = openssl_x509_read($certData);
            if ($cert === false) {
                throw new CraftException("Invalid certificate format");
            }
            openssl_x509_export($cert, $certData, false);
        }

        return [$certData];
    }

    private function loadPrivateKey()
    {
        if (!file_exists($this->privateKeyPath)) {
            throw new CraftException("Private key file not found: {$this->privateKeyPath}");
        }

        $keyData = file_get_contents($this->privateKeyPath);
        if ($keyData === false) {
            throw new CraftException("Failed to read private key file");
        }

        $privateKey = openssl_pkey_get_private($keyData);
        if ($privateKey === false) {
            throw new CraftException("Invalid private key format");
        }

        return $privateKey;
    }
}
