<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\ServerNameExtension;
use Php\TlsCraft\Messages\ExtensionType;

class ServerNameExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private string $serverName
    )
    {
    }

    public function create(Context $context): Extension
    {
        $context->setRequestedServerName($this->serverName);
        return new ServerNameExtension($this->serverName);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SERVER_NAME;
    }
}