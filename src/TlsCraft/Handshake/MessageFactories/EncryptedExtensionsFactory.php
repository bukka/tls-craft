<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;

class EncryptedExtensionsFactory extends AbstractMessageFactory
{
    public function create(): EncryptedExtensions
    {
        $extensions = $this->config->getEncryptedExtensions()->createExtensions($this->context);

        return new EncryptedExtensions($extensions);
    }
}
