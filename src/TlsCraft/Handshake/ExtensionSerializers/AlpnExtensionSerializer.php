<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\AlpnExtension;

class AlpnExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(AlpnExtension $extension): string
    {
        $protocolsData = '';
        foreach ($extension->getProtocols() as $protocol) {
            $protocolsData .= chr(strlen($protocol)).$protocol;
        }

        return $this->packData($protocolsData);
    }
}
