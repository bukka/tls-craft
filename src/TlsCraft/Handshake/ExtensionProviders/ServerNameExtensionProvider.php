<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

use const FILTER_VALIDATE_IP;

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
                'will_return' => $requestedName ? 'extension' : 'null',
            ]);

            if (!$requestedName || $this->isIpAddress($requestedName)) {
                return null;
            }

            $context->setServerNameAcknowledged(true);

            return new ServerNameExtension($this->serverName);
        }
    }

    private function isIpAddress(string $name): bool
    {
        return filter_var($name, FILTER_VALIDATE_IP) !== false;
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SERVER_NAME;
    }
}
