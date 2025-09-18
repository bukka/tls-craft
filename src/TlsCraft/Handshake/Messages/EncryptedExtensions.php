<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;

class EncryptedExtensions extends Message
{
    public function __construct(
        public readonly array $extensions // array of Extension
    )
    {
        parent::__construct(HandshakeType::ENCRYPTED_EXTENSIONS);
    }

    public function encode(): string
    {
        return Extension::encodeList($this->extensions);
    }

    public static function decode(string $data): static
    {
        $offset = 0;
        $extensions = Extension::decodeList($data, $offset);
        return new self($extensions);
    }
}