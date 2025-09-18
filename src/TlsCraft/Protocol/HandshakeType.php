<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

/**
 * TLS Handshake Message Types
 */
enum HandshakeType: int
{
    case HELLO_REQUEST = 0;
    case CLIENT_HELLO = 1;
    case SERVER_HELLO = 2;
    case HELLO_VERIFY_REQUEST = 3;
    case NEW_SESSION_TICKET = 4;
    case END_OF_EARLY_DATA = 5;
    case HELLO_RETRY_REQUEST = 6;
    case ENCRYPTED_EXTENSIONS = 8;
    case CERTIFICATE = 11;
    case SERVER_KEY_EXCHANGE = 12;
    case CERTIFICATE_REQUEST = 13;
    case SERVER_HELLO_DONE = 14;
    case CERTIFICATE_VERIFY = 15;
    case CLIENT_KEY_EXCHANGE = 16;
    case FINISHED = 20;
    case CERTIFICATE_URL = 21;
    case CERTIFICATE_STATUS = 22;
    case SUPPLEMENTAL_DATA = 23;
    case KEY_UPDATE = 24;
    case MESSAGE_HASH = 254;

    public function toByte(): string
    {
        return chr($this->value);
    }

    public static function fromByte(string $byte): self
    {
        return self::from(ord($byte));
    }
}
