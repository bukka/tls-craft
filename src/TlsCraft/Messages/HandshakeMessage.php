<?php

namespace Php\TlsCraft\Messages;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class HandshakeMessage
{
    public function __construct(
        public readonly HandshakeType $type
    )
    {
    }

    abstract public function encode(): string;

    abstract public static function decode(string $data): static;

    public function toWire(): string
    {
        $payload = $this->encode();
        $length = strlen($payload);

        if ($length > 0xFFFFFF) {
            throw new ProtocolViolationException("Handshake message too large");
        }

        return $this->type->toByte() .
            substr(pack('N', $length), 1) . // 3-byte length
            $payload;
    }

    public static function fromWire(string $data, int &$offset = 0): static
    {
        if (strlen($data) - $offset < 4) {
            throw new CraftException("Insufficient data for handshake header");
        }

        $type = HandshakeType::fromByte($data[$offset]);
        $length = unpack('N', "\x00" . substr($data, $offset + 1, 3))[1];
        $offset += 4;

        if (strlen($data) - $offset < $length) {
            throw new CraftException("Insufficient data for handshake payload");
        }

        $payload = substr($data, $offset, $length);
        $offset += $length;

        return match ($type) {
            HandshakeType::CLIENT_HELLO => ClientHello::decode($payload),
            HandshakeType::SERVER_HELLO => ServerHello::decode($payload),
            HandshakeType::ENCRYPTED_EXTENSIONS => EncryptedExtensions::decode($payload),
            HandshakeType::CERTIFICATE => Certificate::decode($payload),
            HandshakeType::CERTIFICATE_VERIFY => CertificateVerify::decode($payload),
            HandshakeType::FINISHED => Finished::decode($payload),
            HandshakeType::KEY_UPDATE => KeyUpdate::decode($payload),
            default => throw new CraftException("Unsupported handshake type: {$type->name}")
        };
    }
}