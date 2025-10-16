<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;

class ServerNameExtensionParser
{
    public function parse(string $data): ServerNameExtension
    {
        $offset = 0;

        // Server name list length
        $listLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // Name type (should be 0 for hostname)
        $nameType = ord($data[$offset]);
        ++$offset;

        if ($nameType !== 0) {
            throw new CraftException("Unsupported name type: {$nameType}");
        }

        // Name length
        $nameLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // Server name
        $serverName = substr($data, $offset, $nameLength);

        return new ServerNameExtension($serverName);
    }
}
