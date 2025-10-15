<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class Message
{
    private ?string $rawMessage = null;

    public function __construct(
        public readonly HandshakeType $type,
        public readonly array $extensions = [],
    ) {
    }

    abstract public function encode(): string;

    public function toWire(): string
    {
        if ($this->rawMessage === null) {
            $payload = $this->encode();
            $length = strlen($payload);

            if ($length > 0xFFFFFF) {
                throw new ProtocolViolationException('Handshake message too large');
            }

            $this->rawMessage = $this->type->toByte().
                substr(pack('N', $length), 1). // 3-byte length
                $payload;
        }

        return $this->rawMessage;
    }

    public function getExtension(ExtensionType $type): ?Extension
    {
        return array_find($this->extensions, fn (Extension $extension) => $extension->type->value === $type->value);
    }
}
