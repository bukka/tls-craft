<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;
use Php\TlsCraft\Protocol\HandshakeType;

/**
 * Serializer for EndOfEarlyData messages
 */
class EndOfEarlyDataSerializer extends AbstractMessageSerializer
{
    public function serialize(EndOfEarlyDataMessage $message): string
    {
        // EndOfEarlyData has no body - just return empty string
        return '';
    }
}
