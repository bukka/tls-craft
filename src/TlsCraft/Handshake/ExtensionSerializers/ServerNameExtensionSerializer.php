<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;

class ServerNameExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(ServerNameExtension $extension): string
    {
        $serverName = $extension->getServerName();

        // Server name list length (2 bytes)
        // Name type (1 byte) - 0 for hostname
        // Name length (2 bytes)
        // Name data
        $nameData = chr(0).pack('n', strlen($serverName)).$serverName;

        return $this->packData($nameData);
    }
}
