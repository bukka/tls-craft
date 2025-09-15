<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Protocol\ProtocolOrchestrator;
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
        $this->config = $config ?? $this->createDefaultConfig();

        $this->addDefaultClientExtensions();
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    public function connect(float $timeout = 30.0, ?FlowController $flowController = null): Session
    {
        // Establish TCP connection
        $connection = Connection::connect($this->hostname, $this->port, $timeout);

        // Create state tracker and validator
        $stateTracker = new StateTracker(true); // isClient = true
        $validator = $this->config->customValidator ??
            new ProtocolValidator($this->config->allowProtocolViolations);

        // Create handshake context
        $context = new Context(true);

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
            $connection,
            $flowController
        );

        // Perform handshake
        $orchestrator->performClientHandshake();

        return new Session($connection, $orchestrator);
    }

    private function createDefaultConfig(): Config
    {
        return new Config();
    }

    private function addDefaultClientExtensions(): void
    {
        // Add SNI extension for hostname
        if ($this->hostname && !$this->hasExtension(0)) {
            $this->config->clientHelloExtensions->add(
                new SNIExtensionProvider($this->hostname)
            );
        }

        // Add key share extension
        if (!$this->hasExtension(51)) {
            $this->config->clientHelloExtensions->add(
                new KeyShareExtensionProvider($this->config->supportedGroups)
            );
        }

        // Add signature algorithms extension
        if (!$this->hasExtension(13)) {
            $this->config->clientHelloExtensions->add(
                new SignatureAlgorithmsProvider($this->config->signatureAlgorithms)
            );
        }
    }

    private function hasExtension(int $type): bool
    {
        foreach ($this->config->clientHelloExtensions->getProviders() as $provider) {
            if ($provider->getExtensionType() === $type) {
                return true;
            }
        }
        return false;
    }
}