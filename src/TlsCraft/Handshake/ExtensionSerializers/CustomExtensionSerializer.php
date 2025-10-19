<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\CustomExtension;

class CustomExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(CustomExtension $extension): string
    {
        return $extension->getRawData();
    }
}
