<?php

declare(strict_types=1);

namespace Php\TlsCraft\State;

/**
 * Overall connection state
 */
enum HandshakeState: string
{
    case START = 'start';
    case WAIT_CLIENT_HELLO = 'wait_client_hello';
    case WAIT_SERVER_HELLO = 'wait_server_hello';
    case WAIT_ENCRYPTED_EXTENSIONS = 'wait_encrypted_extensions';
    case WAIT_CERTIFICATE = 'wait_certificate';
    case WAIT_CERTIFICATE_VERIFY = 'wait_certificate_verify';
    case WAIT_FINISHED = 'wait_finished';
    case WAIT_FLIGHT2 = 'wait_flight2';
    case CONNECTED = 'connected';

    public function isClientState(): bool
    {
        return match ($this) {
            self::WAIT_SERVER_HELLO,
            self::WAIT_ENCRYPTED_EXTENSIONS,
            self::WAIT_CERTIFICATE,
            self::WAIT_CERTIFICATE_VERIFY,
            self::WAIT_FINISHED => true,
            default => false
        };
    }

    public function isServerState(): bool
    {
        return match ($this) {
            self::WAIT_CLIENT_HELLO,
            self::WAIT_FLIGHT2 => true,
            default => false
        };
    }
}