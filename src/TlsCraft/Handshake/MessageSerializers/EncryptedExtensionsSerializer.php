<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;

class EncryptedExtensionsSerializer extends AbstractMessageSerializer
{
    public function serialize(EncryptedExtensionsMessage $message): string
    {
        return $this->extensionFactory->encodeExtensionList($message->extensions);
    }
}
