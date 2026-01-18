<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;

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
