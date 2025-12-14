<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;

class Server
{
    private Config $config;
    private ConnectionFactory $connectionFactory;
    private DependencyContainer $dependencyContainer;
    private ?Connection $serverConnection = null;

    public function __construct(
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        ?DependencyContainer $dependencyContainer = null,
        bool $debug = false,
    ) {
        if ($debug) {
            Logger::enable();
        }
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

        // Load certificate from config
        $context->loadCertificateFromConfig();

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
}
