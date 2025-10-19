<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class EncryptedExtensions extends Message
{
    public function __construct(
        array $extensions, // array of Extension
    ) {
        parent::__construct(HandshakeType::ENCRYPTED_EXTENSIONS, $extensions);
    }
}
