<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\ServerNameExtension;

class ServerNameExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private string $serverName
    )
    {
    }

    public function create(Context $context): Extension
    {
        return new ServerNameExtension($this->serverName);
    }
}