<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;

class PskKeyExchangeModesParser
{
    public function parse(string $data): PskKeyExchangeModesExtension
    {
        $offset = 0;

        // Length
        $length = unpack('C', substr($data, $offset, 1))[1];
        ++$offset;

        // Modes
        $modes = [];
        for ($i = 0; $i < $length; ++$i) {
            $modes[] = unpack('C', substr($data, $offset, 1))[1];
            ++$offset;
        }

        return new PskKeyExchangeModesExtension($modes);
    }
}
