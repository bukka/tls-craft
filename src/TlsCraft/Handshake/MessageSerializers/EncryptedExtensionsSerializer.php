<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;

class EncryptedExtensionsSerializer extends AbstractMessageSerializer
{
    public function serialize(EncryptedExtensions $message): string
    {
        return $this->extensionFactory->encodeExtensionList($message->extensions);
    }
}
