<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;

class EncryptedExtensions extends Message
{
    public function __construct(
        public readonly array $extensions, // array of Extension
    ) {
        parent::__construct(HandshakeType::ENCRYPTED_EXTENSIONS);
    }

    public function encode(): string
    {
        return Extension::encodeList($this->extensions);
    }
}
