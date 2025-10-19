<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;

class SupportedVersionsExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(SupportedVersionsExtension $extension): string
    {
        if (!$this->context->isClient()) {
            return $extension->getVersions()[0]->toBytes();
        }

        $versionsData = '';

        foreach ($extension->getVersions() as $version) {
            $versionsData .= $version->toBytes();
        }

        return $this->packData($versionsData, 'C');
    }
}
