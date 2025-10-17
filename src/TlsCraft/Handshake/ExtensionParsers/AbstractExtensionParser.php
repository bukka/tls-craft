<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Context;

class AbstractExtensionParser
{
    public function __construct(protected Context $context)
    {
    }
}
