<?php

namespace Php\TlsCraft\Generators;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Messages\HandshakeMessage;

class MessageGeneratorOrchestrator
{
    /** @var MessageGenerator[] */
    private array $generators = [];

    public function __construct(Context $context, Config $config)
    {
        $this->generators[] = new ClientHelloGenerator($context, $config);
        $this->generators[] = new ServerHelloGenerator($context, $config);
        $this->generators[] = new KeyUpdateGenerator($context, $config);
        // Add more generators as needed
    }

    public function generate(string $messageType, array $params = []): HandshakeMessage
    {
        foreach ($this->generators as $generator) {
            if ($generator->canGenerate($messageType)) {
                return $generator->generate($params);
            }
        }

        throw new \InvalidArgumentException("No generator found for message type: {$messageType}");
    }

    public function addGenerator(MessageGenerator $generator): void
    {
        $this->generators[] = $generator;
    }
}