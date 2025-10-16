<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;

/**
 * ALPN Extension
 */
class AlpnExtension extends Extension
{
    public function __construct(
        private array $protocols,
    ) {
        parent::__construct(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    }

    public function getProtocols(): array
    {
        return $this->protocols;
    }

    public function encode(): string
    {
        $protocolsData = '';
        foreach ($this->protocols as $protocol) {
            $protocolsData .= chr(strlen($protocol)).$protocol;
        }

        return pack('n', strlen($protocolsData)).$protocolsData;
    }
}
