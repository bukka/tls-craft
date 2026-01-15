<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Connection\ConnectionFactory;
use Php\TlsCraft\Crypto\CryptoFactory;
use Php\TlsCraft\Handshake\ExtensionFactory;
use Php\TlsCraft\Handshake\HandshakeTranscript;
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\MessageSerializer;
use Php\TlsCraft\Handshake\ProcessorFactory;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Handshake\PskBinderCalculator;
use Php\TlsCraft\Record\LayerFactory;
use Php\TlsCraft\Record\RecordFactory;
use Php\TlsCraft\State\ProtocolValidator;
use Php\TlsCraft\State\StateTracker;

final class DependencyContainer
{
    public function __construct(
        private bool $isClient,
        private ?Config $config = null,
        private ?ConnectionFactory $connectionFactory = null,
    ) {
    }
    private ?Config $cfg = null;
    private ?ConnectionFactory $connFactory = null;
    private ?CryptoFactory $cryptoFactory = null;
    private ?LayerFactory $layerFactory = null;
    private ?RecordFactory $recordFactory = null;
    private ?Context $context = null;
    private ?ProtocolValidator $validator = null;
    private ?StateTracker $stateTracker = null;
    private ?ExtensionFactory $extensionFactory = null;
    private ?MessageFactory $messageFactory = null;
    private ?MessageSerializer $messageSerializer = null;
    private ?ProcessorFactory $processorFactory = null;
    private ?ProcessorManager $processorManager = null;

    public function getConfig(): Config
    {
        return $this->cfg ??= ($this->config ?? new Config());
    }

    public function getConnectionFactory(): ConnectionFactory
    {
        return $this->connFactory ??= ($this->connectionFactory ?? new ConnectionFactory());
    }

    public function getCryptoFactory(): CryptoFactory
    {
        return $this->cryptoFactory ??= new CryptoFactory();
    }

    public function getLayerFactory(): LayerFactory
    {
        return $this->layerFactory ??= new LayerFactory();
    }

    public function getRecordFactory(): RecordFactory
    {
        return $this->recordFactory ??= new RecordFactory();
    }

    public function getContext(): Context
    {
        if ($this->context !== null) {
            return $this->context;
        }

        $context = new Context(
            $this->isClient,
            $this->getConfig(),
            $this->getCryptoFactory(),
            new HandshakeTranscript(),
        );

        // Set PSK binder calculator after KeySchedule is available
        // Note: KeySchedule is created when cipher suite is negotiated,
        // so we create a lazy wrapper here
        $context->setPskBinderCalculator(
            new PskBinderCalculator($context),
        );

        return $this->context = $context;
    }

    public function getValidator(): ProtocolValidator
    {
        return $this->validator ??= ($this->getConfig()->hasCustomValidator()
            ? $this->getConfig()->getCustomValidator()
            : new ProtocolValidator($this->getConfig()->isAllowProtocolViolations()));
    }

    public function getStateTracker(): StateTracker
    {
        return $this->stateTracker ??= new StateTracker($this->isClient);
    }

    public function getExtensionFactory(): ExtensionFactory
    {
        return $this->extensionFactory ??= new ExtensionFactory($this->getContext());
    }

    public function getMessageFactory(): MessageFactory
    {
        return $this->messageFactory ??= new MessageFactory($this->getContext(), $this->getExtensionFactory());
    }

    public function getMessageSerializer(): MessageSerializer
    {
        return $this->messageSerializer ??= new MessageSerializer($this->getContext(), $this->getExtensionFactory());
    }

    public function getProcessorFactory(): ProcessorFactory
    {
        return $this->processorFactory ??= new ProcessorFactory($this->getContext());
    }

    public function getProcessorManager(): ProcessorManager
    {
        return $this->processorManager ??= new ProcessorManager($this->getProcessorFactory());
    }

    public function reset(): void
    {
        $this->context = null;
        $this->stateTracker = null;
        $this->validator = null;
        $this->extensionFactory = null;
        $this->messageFactory = null;
        $this->messageSerializer = null;
        $this->processorFactory = null;
        $this->processorManager = null;
    }
}
