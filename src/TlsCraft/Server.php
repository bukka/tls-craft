<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;

class Server
{
    private string $certificatePath;
    private string $privateKeyPath;
    private Config $config;
    private ConnectionFactory $connectionFactory;
    private DependencyContainer $dependencyContainer;
    private ?Connection $serverConnection = null;

    public function __construct(
        string $certificatePath,
        string $privateKeyPath,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        ?DependencyContainer $dependencyContainer = null,
        bool $debug = false,
    ) {
        if ($debug) {
            Logger::enable();
        }
        $this->certificatePath = $certificatePath;
        $this->privateKeyPath = $privateKeyPath;
        $this->config = $config ?? new Config();
        $this->connectionFactory = $connectionFactory ?? new ConnectionFactory();
        $this->dependencyContainer = $dependencyContainer ?? new DependencyContainer(
            false,
            $this->config,
            $this->connectionFactory,
        );
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
        RuntimeEnvironment::assertOpenSsl3();

        $clientConnection = $this->serverConnection->accept($timeout);

        $stateTracker = $this->dependencyContainer->getStateTracker();
        $validator = $this->dependencyContainer->getValidator();
        $context = $this->dependencyContainer->getContext();
        $cryptoFactory = $this->dependencyContainer->getCryptoFactory();
        $layerFactory = $this->dependencyContainer->getLayerFactory();
        $recordFactory = $this->dependencyContainer->getRecordFactory();
        $messageFactory = $this->dependencyContainer->getMessageFactory();
        $messageSerializer = $this->dependencyContainer->getMessageSerializer();
        $processorManager = $this->dependencyContainer->getProcessorManager();

        $context->setCertificateChainFromFile($this->certificatePath);
        $context->setPrivateKeyFromFile($this->privateKeyPath);

        $orchestrator = new ProtocolOrchestrator(
            $stateTracker,
            $validator,
            $context,
            $processorManager,
            $cryptoFactory,
            $layerFactory,
            $recordFactory,
            $messageFactory,
            $messageSerializer,
            $clientConnection,
            $flowController,
        );

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

        $cert = openssl_x509_read($certData);
        if ($cert === false) {
            throw new CraftException('Invalid certificate format');
        }

        // Export to PEM without text (use true or omit the parameter)
        if (!openssl_x509_export($cert, $pemData, true)) {
            throw new CraftException('Failed to export certificate');
        }

        // Convert PEM to DER by removing headers and decoding base64
        $base64Data = preg_replace(
            ['/-----BEGIN CERTIFICATE-----/', '/-----END CERTIFICATE-----/', '/\s+/'],
            '',
            $pemData,
        );

        $derData = base64_decode($base64Data);
        if ($derData === false || empty($derData)) {
            throw new CraftException('Failed to decode certificate to DER format');
        }

        return [$derData];
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
