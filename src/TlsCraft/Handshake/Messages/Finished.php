<?php

namespace Php\TlsCraft\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class Finished extends Message
{
    public function __construct(
        public readonly string $verifyData
    )
    {
        parent::__construct(HandshakeType::FINISHED);
    }

    public function encode(): string
    {
        return $this->verifyData;
    }

    public static function decode(string $data): static
    {
        return new self($data);
    }
}