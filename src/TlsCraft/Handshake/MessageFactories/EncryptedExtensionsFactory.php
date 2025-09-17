<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\EncryptedExtensions;

class EncryptedExtensionsFactory extends AbstractMessageFactory
{
    public function create(): EncryptedExtensions
    {
        $extensions = $this->config->encryptedExtensions->createExtensions($this->context);
        return new EncryptedExtensions($extensions);
    }
}
