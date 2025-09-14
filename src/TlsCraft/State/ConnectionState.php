<?php

declare(strict_types=1);

namespace Php\TlsCraft\State;

/**
 * Overall connection state
 */
enum ConnectionState: string
{
    case INITIAL = 'initial';
    case HANDSHAKING = 'handshaking';
    case CONNECTED = 'connected';
    case CLOSING = 'closing';
    case CLOSED = 'closed';
    case ERROR = 'error';

    public function canTransitionTo(self $newState): bool
    {
        return match ($this) {
            self::INITIAL => $newState === self::HANDSHAKING,
            self::HANDSHAKING => in_array($newState, [self::CONNECTED, self::ERROR, self::CLOSED]),
            self::CONNECTED => in_array($newState, [self::CLOSING, self::ERROR, self::CLOSED]),
            self::CLOSING => in_array($newState, [self::CLOSED, self::ERROR]),
            self::CLOSED => false,
            self::ERROR => $newState === self::CLOSED,
        };
    }
}