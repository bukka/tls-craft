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
        $keyShares = [];
        $offset = 0;

        if ($this->context->isClient()) {
            // Client parsing ServerHello: single KeyShare entry (no length prefix)
            $keyShares[] = KeyShare::decode($data, $offset);
        } else {
            // Server parsing ClientHello: list format with 2-byte length prefix
            $listLength = unpack('n', substr($data, 0, 2))[1];
            $offset = 2;
            $endOffset = $offset + $listLength;

            while ($offset < $endOffset) {
                $keyShares[] = KeyShare::decode($data, $offset);
            }
        }

        return new KeyShareExtension($keyShares);
    }
}
