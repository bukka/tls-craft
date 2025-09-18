<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\AlpnExtension;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;

class AlpnExtensionProvider implements ExtensionProvider
{
    public function __construct(private readonly array $protocols = [])
    {
    }

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            $context->setClientOfferedProtocols($this->protocols);
            return new AlpnExtension($this->protocols);
        }

        $selectedProtocol = $context->getSelectedProtocol();
        if (is_null($selectedProtocol)) {
            return null;
        }

        return new AlpnExtension([$selectedProtocol]);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
    }
}