<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CryptoFactory;
use Php\TlsCraft\Handshake\ExtensionFactory;
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\ProcessorFactory;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;
use Php\TlsCraft\Record\LayerFactory;
use Php\TlsCraft\Record\RecordFactory;
use Php\TlsCraft\State\ProtocolValidator;
use Php\TlsCraft\State\StateTracker;

class Client
{
    private string $hostname;
    private int $port;
    private Config $config;
    private ConnectionFactory $connectionFactory;

    public function __construct(
        string $hostname,
        int $port,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
    ) {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->config = $config ?? new Config();
        $this->connectionFactory = $connectionFactory ?? new ConnectionFactory();
    }

    public function connect(float $timeout = 30.0, ?FlowController $flowController = null): Session
    {
        // Establish TCP connection
        $connection = $this->connectionFactory->connect($this->hostname, $this->port, $timeout);

        // Create a state tracker and validator
        $stateTracker = new StateTracker(true); // isClient = true
        $validator = $this->config->hasCustomValidator() ? $this->config->getCustomValidator() : new ProtocolValidator(
            $this->config->isAllowProtocolViolations(),
        );

        // Create a crypto factory
        $cryptoFactory = new CryptoFactory();

        // Create a handshake context
        $context = new Context(true, $this->config, $cryptoFactory);
        $layerFactory = new LayerFactory();
        $recordFactory = new RecordFactory();
        $extensionFactory = new ExtensionFactory($context);
        $messageFactory = new MessageFactory($context, $extensionFactory);
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
            $connection,
            $flowController,
        );

        // Perform handshake
        $orchestrator->performClientHandshake();

        return new Session($connection, $orchestrator);
    }
}
