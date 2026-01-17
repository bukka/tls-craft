<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

/**
 * EndOfEarlyData Message (RFC 8446 Section 4.5)
 *
 * This message is sent by the client after all early data (0-RTT data)
 * has been transmitted. It has an empty body.
 *
 * struct {} EndOfEarlyData;
 *
 * This message is encrypted under the early_traffic_keys and indicates
 * that the client is transitioning to handshake keys.
 */
class EndOfEarlyDataMessage extends Message
{
    public function __construct()
    {
        parent::__construct(HandshakeType::END_OF_EARLY_DATA);
    }

    /**
     * Create new EndOfEarlyData message
     */
    public static function create(): self
    {
        return new self();
    }
}
