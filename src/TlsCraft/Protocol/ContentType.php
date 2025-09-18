<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

/**
 * TLS Content Types
 */
enum ContentType: int
{
    case CHANGE_CIPHER_SPEC = 20;
    case ALERT = 21;
    case HANDSHAKE = 22;
    case APPLICATION_DATA = 23;
    case HEARTBEAT = 24; // RFC 6520

    public function toByte(): string
    {
        return chr($this->value);
    }

    public static function fromByte(string $byte): self
    {
        return self::from(ord($byte));
    }
}
