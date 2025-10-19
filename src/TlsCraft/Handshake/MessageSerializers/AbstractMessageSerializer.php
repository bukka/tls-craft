<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\ExtensionFactory;

abstract class AbstractMessageSerializer
{
    public function __construct(protected Context $context, protected ExtensionFactory $extensionFactory)
    {
    }
}
