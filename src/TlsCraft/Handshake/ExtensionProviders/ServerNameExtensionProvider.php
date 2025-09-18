<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\ExtensionType;

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
