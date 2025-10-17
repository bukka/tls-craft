<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;

class Client
{
    private string $hostname;
    private int $port;
    private Config $config;
    private ConnectionFactory $connectionFactory;
    private DependencyContainer $dependencyContainer;

    public function __construct(
        string $hostname,
        int $port,
        ?Config $config = null,
        ?ConnectionFactory $connectionFactory = null,
        ?DependencyContainer $dependencyContainer = null,
    ) {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->config = $config ?? new Config();
        $this->connectionFactory = $connectionFactory ?? new ConnectionFactory();
        $this->dependencyContainer = $dependencyContainer ?? new DependencyContainer(
            false,
            $this->config,
            $this->connectionFactory
        );
    }

    public function connect(float $timeout = 30.0, ?FlowController $flowController = null): Session
    {
        RuntimeEnvironment::assertOpenSsl3();

        $connection = $this->connectionFactory->connect($this->hostname, $this->port, $timeout);

        $stateTracker     = $this->dependencyContainer->getStateTracker();
        $validator        = $this->dependencyContainer->getValidator();
        $context          = $this->dependencyContainer->getContext();
        $layerFactory     = $this->dependencyContainer->getLayerFactory();
        $recordFactory    = $this->dependencyContainer->getRecordFactory();
        $messageFactory   = $this->dependencyContainer->getMessageFactory();
        $processorManager = $this->dependencyContainer->getProcessorManager();

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

        $orchestrator->performClientHandshake();
        return new Session($connection, $orchestrator);
    }
}
