<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;
use Php\TlsCraft\Protocol\HandshakeType;

class EncryptedExtensionsFactory extends AbstractMessageFactory
{
    public function create(): EncryptedExtensions
    {
        $extensions = $this->config->getEncryptedExtensions()->createExtensions($this->context);

        return new EncryptedExtensions($extensions);
    }

    public function fromWire(string $data): EncryptedExtensions
    {
        $payload = $this->parseHandshake($data, HandshakeType::ENCRYPTED_EXTENSIONS);

        $offset = 0;
        $extensions = Extension::decodeList($payload, $offset);

        return new EncryptedExtensions($extensions);
    }
}
