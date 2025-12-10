<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;

class EncryptedExtensionsFactory extends AbstractMessageFactory
{
    public function create(): EncryptedExtensionsMessage
    {
        $extensions = $this->config->getEncryptedExtensions()->createExtensions($this->context);

        return new EncryptedExtensionsMessage($extensions);
    }
}
