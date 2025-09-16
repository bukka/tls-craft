<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Messages\ExtensionType;

/**
 * ALPN Extension
 */
class AlpnExtension extends Extension
{
    public function __construct(
        private array $protocols
    )
    {
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
            $protocolsData .= chr(strlen($protocol)) . $protocol;
        }
        return pack('n', strlen($protocolsData)) . $protocolsData;
    }

    public static function decode(string $data): static
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;
        $endOffset = $offset + $listLength;

        $protocols = [];
        while ($offset < $endOffset) {
            $protocolLength = ord($data[$offset]);
            $offset += 1;
            $protocols[] = substr($data, $offset, $protocolLength);
            $offset += $protocolLength;
        }

        return new self($protocols);
    }
}