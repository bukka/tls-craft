<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;

class AbstractMessageFactory
{
    public function __construct(protected Context $context, protected Config $config)
    {
    }
}