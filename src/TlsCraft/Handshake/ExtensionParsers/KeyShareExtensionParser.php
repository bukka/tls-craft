<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Crypto\KeyShare;
use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;

/**
 * Key Share Extension parser
 */
class KeyShareExtensionParser extends AbstractExtensionParser
{
    public function parse(string $data): KeyShareExtension
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;

        $keyShares = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $keyShares[] = KeyShare::decode($data, $offset);
        }

        return new KeyShareExtension($keyShares);
    }
}
