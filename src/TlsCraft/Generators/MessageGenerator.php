<?php

namespace Php\TlsCraft\Generators;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Messages\HandshakeMessage;

abstract class MessageGenerator
{
    public function __construct(
        protected Context $context,
        protected Config $config
    ) {}

    abstract public function canGenerate(string $messageType): bool;
    abstract public function generate(array $params = []): HandshakeMessage;
}