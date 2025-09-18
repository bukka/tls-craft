<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\{Extension, ServerNameExtension};
use Php\TlsCraft\Messages\ExtensionType;

class ServerNameExtensionProvider implements ExtensionProvider
{
    public function __construct(private readonly string $serverName = '')
    {
    }

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            $context->setRequestedServerName($this->serverName);
            return new ServerNameExtension($this->serverName);
        } else {
            // Check whether the client sent SNI
            $requestedName = $context->getRequestedServerName();
            if (!$requestedName) {
                return null;
            }

            $context->setServerNameAcknowledged(true);
            return new ServerNameExtension($this->serverName);
        }
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SERVER_NAME;
    }
}
