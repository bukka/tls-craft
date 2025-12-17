<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;

/**
 * Serializer for PskKeyExchangeModes extension
 */
class PskKeyExchangeModesExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(PskKeyExchangeModesExtension $extension): string
    {
        // Length (1 byte) + modes
        $modes = pack('C*', ...$extension->modes);

        return pack('C', count($extension->modes)).$modes;
    }
}
