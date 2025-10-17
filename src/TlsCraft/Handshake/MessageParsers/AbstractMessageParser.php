<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ExtensionFactory;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class AbstractMessageParser
{
    public function __construct(protected Context $context, protected ExtensionFactory $extensionFactory)
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
