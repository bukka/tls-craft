<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;

class KeyShareExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(KeyShareExtension $extension): string
    {
        $keyShares = $extension->getKeyShares();

        if (!$this->context->isClient()) {
            return $keyShares[0]->encode();
        }

        $keySharesData = '';
        foreach ($keyShares as $keyShare) {
            $keySharesData .= $keyShare->encode();
        }

        return $this->packData($keySharesData);
    }
}
