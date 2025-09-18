<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CryptoFactory;
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\ProcessorFactory;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Handshake\ExtensionProviders\KeyShareExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SignatureAlgorithmsProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\ServerNameExtensionProvider;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;
use Php\TlsCraft\Record\LayerFactory;
use Php\TlsCraft\State\ProtocolValidator;
use Php\TlsCraft\State\StateTracker;

class Client
{
    private string $hostname;
    private int $port;
    private Config $config;

    public function __construct(
        string $hostname,
        int $port,
        ?Config $config = null
    ) {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->config = $config ?? new Config();
    }

    public function connect(float $timeout = 30.0, ?FlowController $flowController = null): Session
    {
        // Establish TCP connection
        $connection = Connection::connect($this->hostname, $this->port, $timeout);

        // Create a state tracker and validator
        $stateTracker = new StateTracker(true); // isClient = true
        $validator = $this->config->hasCustomValidator() ??
            new ProtocolValidator($this->config->isAllowProtocolViolations());

        // Create a crypto factory
        $cryptoFactory = new CryptoFactory();

        // Create a handshake context
        $context = new Context(true, $this->config, $cryptoFactory);
        $layerFactory = new LayerFactory();
        $messageFactory = new MessageFactory($context);
        $processorManager = new ProcessorManager(new ProcessorFactory($context));

        // Create protocol orchestrator
        $orchestrator = new ProtocolOrchestrator(
            $stateTracker,
            $validator,
            $context,
            $processorManager,
            $layerFactory,
            $messageFactory,
            $connection,
            $flowController
        );

        // Perform handshake
        $orchestrator->performClientHandshake();

        return new Session($connection, $orchestrator);
    }
}