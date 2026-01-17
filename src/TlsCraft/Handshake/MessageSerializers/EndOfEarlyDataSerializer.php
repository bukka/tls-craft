<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;
use Php\TlsCraft\Protocol\HandshakeType;

/**
 * Serializer for EndOfEarlyData messages
 *
 * EndOfEarlyData has an empty body, so serialization is just the header:
 * - 1 byte: handshake type (5)
 * - 3 bytes: length (0)
 */
class EndOfEarlyDataSerializer extends AbstractMessageSerializer
{
    public function serialize(EndOfEarlyDataMessage $message): string
    {
        // Type (1 byte) + Length (3 bytes, always 0)
        return HandshakeType::END_OF_EARLY_DATA->toByte() . "\x00\x00\x00";
    }
}
