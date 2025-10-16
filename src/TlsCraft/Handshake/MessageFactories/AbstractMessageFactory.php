<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class AbstractMessageFactory
{
    public function __construct(protected Context $context, protected Config $config)
    {
    }
}
