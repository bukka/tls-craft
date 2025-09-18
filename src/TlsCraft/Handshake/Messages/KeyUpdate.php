<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdate extends Message
{
    public function __construct(
        public readonly bool $requestUpdate
    )
    {
        parent::__construct(HandshakeType::KEY_UPDATE);
    }

    public function encode(): string
    {
        return chr($this->requestUpdate ? 1 : 0);
    }

    public static function decode(string $data): static
    {
        if (strlen($data) < 1) {
            throw new CraftException("Invalid KeyUpdate message length");
        }

        return new self(ord($data[0]) === 1);
    }
}