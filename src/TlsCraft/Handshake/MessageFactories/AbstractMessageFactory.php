<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class AbstractMessageFactory
{
    public function __construct(protected Context $context, protected Config $config)
    {
    }

    protected function parseHandshake(string $data, HandshakeType $expectedType): string
    {
        if (strlen($data) < 4) {
            throw new CraftException('Insufficient data for handshake header');
        }

        $type = HandshakeType::fromByte($data[0]);
        $length = unpack('N', "\x00".substr($data, 1, 3))[1];

        if (strlen($data) < 4 + $length) {
            throw new CraftException('Insufficient data for handshake payload');
        }

        if ($expectedType !== $type) {
            throw new CraftException(
                "Handshake type mismatch: expected {$expectedType->name}, got {$type->name}"
            );
        }

        return substr($data, 4, $length);
    }
}
