<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CryptoFactory;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\ProcessorFactory;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;
use Php\TlsCraft\Record\LayerFactory;
use Php\TlsCraft\Record\RecordFactory;
use Php\TlsCraft\State\ProtocolValidator;
use Php\TlsCraft\State\StateTracker;

class Server
{
    private string $certificatePath;
    private string $privateKeyPath;
    private Config $config;
    private ConnectionFactory $connectionFactory;
    private ?Connection $serverConnection = null;

    public function __construct(
        string $certificatePath,
        string $privateKeyPath,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
    ) {
        $this->certificatePath = $certificatePath;
        $this->privateKeyPath = $privateKeyPath;
        $this->config = $config ?? new Config();
        $this->connectionFactory = $connectionFactory ?? new ConnectionFactory();
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    public function listen(string $address, int $port): void
    {
        $this->serverConnection = $this->connectionFactory->server(
            $address,
            $port,
            $this->config->getConnectionOptions(),
        );
    }

    public function accept(?float $timeout = null, ?FlowController $flowController = null): Session
    {
        if (!$this->serverConnection) {
            throw new CraftException('Server not listening');
        }

        // Accept TCP connection
        $clientConnection = $this->serverConnection->accept($timeout);

        // Create a state tracker for this connection
        $stateTracker = new StateTracker(false); // isClient = false

        // Create protocol validator
        $validator = $this->config->hasCustomValidator() ?? new ProtocolValidator($this->config->isAllowProtocolViolations());

        // Create a crypto factory
        $cryptoFactory = new CryptoFactory();

        // Create handshake context
        $context = new Context(false, $this->config, $cryptoFactory); // isClient = false
        $context->setCertificateChain($this->loadCertificateChain());
        $context->setPrivateKey($this->loadPrivateKey());

        $layerFactory = new LayerFactory();
        $recordFactory = new RecordFactory();
        $messageFactory = new MessageFactory($context);
        $processorManager = new ProcessorManager(new ProcessorFactory($context));

        // Create protocol orchestrator
        $orchestrator = new ProtocolOrchestrator(
            $stateTracker,
            $validator,
            $context,
            $processorManager,
            $layerFactory,
            $recordFactory,
            $messageFactory,
            $clientConnection,
            $flowController,
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

    private function loadCertificateChain(): array
    {
        if (!file_exists($this->certificatePath)) {
            throw new CraftException("Certificate file not found: {$this->certificatePath}");
        }

        $certData = file_get_contents($this->certificatePath);
        if ($certData === false) {
            throw new CraftException('Failed to read certificate file');
        }

        // Convert PEM to DER if needed
        if (str_contains($certData, '-----BEGIN CERTIFICATE-----')) {
            $cert = openssl_x509_read($certData);
            if ($cert === false) {
                throw new CraftException('Invalid certificate format');
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
            throw new CraftException('Failed to read private key file');
        }

        $privateKey = openssl_pkey_get_private($keyData);
        if ($privateKey === false) {
            throw new CraftException('Invalid private key format');
        }

        return $privateKey;
    }
}
