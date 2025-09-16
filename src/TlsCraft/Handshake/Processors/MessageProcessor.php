<?php

namespace Php\TlsCraft\Messages\Processors;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;

class MessageProcessor
{
    public function __construct(protected Context $context, protected Config $config)
    {
    }
}