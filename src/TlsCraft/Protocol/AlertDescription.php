<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

/**
 * TLS Alert Descriptions
 */
enum AlertDescription: int
{
    case CLOSE_NOTIFY = 0;
    case UNEXPECTED_MESSAGE = 10;
    case BAD_RECORD_MAC = 20;
    case DECRYPTION_FAILED_RESERVED = 21;
    case RECORD_OVERFLOW = 22;
    case DECOMPRESSION_FAILURE_RESERVED = 30;
    case HANDSHAKE_FAILURE = 40;
    case NO_CERTIFICATE_RESERVED = 41;
    case BAD_CERTIFICATE = 42;
    case UNSUPPORTED_CERTIFICATE = 43;
    case CERTIFICATE_REVOKED = 44;
    case CERTIFICATE_EXPIRED = 45;
    case CERTIFICATE_UNKNOWN = 46;
    case ILLEGAL_PARAMETER = 47;
    case UNKNOWN_CA = 48;
    case ACCESS_DENIED = 49;
    case DECODE_ERROR = 50;
    case DECRYPT_ERROR = 51;
    case EXPORT_RESTRICTION_RESERVED = 60;
    case PROTOCOL_VERSION = 70;
    case INSUFFICIENT_SECURITY = 71;
    case INTERNAL_ERROR = 80;
    case INAPPROPRIATE_FALLBACK = 86;
    case USER_CANCELED = 90;
    case NO_RENEGOTIATION_RESERVED = 100;
    case MISSING_EXTENSION = 109;
    case UNSUPPORTED_EXTENSION = 110;
    case CERTIFICATE_UNOBTAINABLE_RESERVED = 111;
    case UNRECOGNIZED_NAME = 112;
    case BAD_CERTIFICATE_STATUS_RESPONSE = 113;
    case BAD_CERTIFICATE_HASH_VALUE_RESERVED = 114;
    case UNKNOWN_PSK_IDENTITY = 115;
    case CERTIFICATE_REQUIRED = 116;
    case NO_APPLICATION_PROTOCOL = 120;

    public function toByte(): string
    {
        return chr($this->value);
    }

    public static function fromByte(string $byte): self
    {
        return self::from(ord($byte));
    }

    public function isFatal(): bool
    {
        return match ($this) {
            self::CLOSE_NOTIFY,
            self::USER_CANCELED => false,
            default => true
        };
    }
}