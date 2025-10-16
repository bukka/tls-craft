<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\AlpnExtension;

/**
 * ALPN Extension parser
 */
class AlpnExtensionParser
{
    public function parse(string $data): AlpnExtension
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;
        $endOffset = $offset + $listLength;

        $protocols = [];
        while ($offset < $endOffset) {
            $protocolLength = ord($data[$offset]);
            ++$offset;
            $protocols[] = substr($data, $offset, $protocolLength);
            $offset += $protocolLength;
        }

        return new AlpnExtension($protocols);
    }
}
