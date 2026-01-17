<?php

declare(strict_types=1);

namespace Php\TlsCraft\State;

/**
 * Handshake state machine states
 *
 * Tracks the current position in the TLS 1.3 handshake, including
 * early data (0-RTT) states.
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

    // Early data (0-RTT) states
    case WAIT_END_OF_EARLY_DATA = 'wait_end_of_early_data';  // Server waiting for EndOfEarlyData

    case CONNECTED = 'connected';

    public function isClientState(): bool
    {
        return match ($this) {
            self::WAIT_SERVER_HELLO,
            self::WAIT_ENCRYPTED_EXTENSIONS,
            self::WAIT_CERTIFICATE,
            self::WAIT_CERTIFICATE_VERIFY,
            self::WAIT_FINISHED => true,
            default => false,
        };
    }

    public function isServerState(): bool
    {
        return match ($this) {
            self::WAIT_CLIENT_HELLO,
            self::WAIT_FLIGHT2,
            self::WAIT_END_OF_EARLY_DATA => true,
            default => false,
        };
    }

    /**
     * Check if this state involves early data processing
     */
    public function isEarlyDataState(): bool
    {
        return $this === self::WAIT_END_OF_EARLY_DATA;
    }
}
