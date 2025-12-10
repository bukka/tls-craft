<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

class ServerNameExtensionProvider implements ExtensionProvider
{
    public function __construct(private readonly string $serverName = '')
    {
    }

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            Logger::debug('ServerNameExtensionProvider: Creating client SNI', [
                'server_name' => $this->serverName,
            ]);
            $context->setRequestedServerName($this->serverName);

            return new ServerNameExtension($this->serverName);
        } else {
            // Check whether the client sent SNI
            $requestedName = $context->getRequestedServerName();
            Logger::debug('ServerNameExtensionProvider: Checking server SNI', [
                'requested_name' => $requestedName,
                'requested_name_is_null' => $requestedName === null,
                'requested_name_is_empty' => $requestedName === '',
                'will_return' => $requestedName ? 'extension' : 'null',
            ]);

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
