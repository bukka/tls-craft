<?php

namespace Php\TlsCraft\Processors;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Messages\HandshakeMessage;

abstract class MessageProcessor
{
    public function __construct(
        protected Context $context,
        protected Config $config
    ) {}

    abstract public function canProcess(HandshakeMessage $message): bool;
    abstract public function process(HandshakeMessage $message): ProcessingResult;
}