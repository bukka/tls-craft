<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use InvalidArgumentException;
use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;
use Php\TlsCraft\Protocol\HandshakeType;

/**
 * Parser for EndOfEarlyData messages
 *
 * EndOfEarlyData has an empty body, so parsing just validates the header.
 */
class EndOfEarlyDataParser extends AbstractMessageParser
{
    public function parse(string $data): EndOfEarlyDataMessage
    {
        // Validate header and get payload (should be empty)
        $payload = $this->parseHandshake($data, HandshakeType::END_OF_EARLY_DATA);

        // EndOfEarlyData should have empty payload
        if ($payload !== '') {
            throw new InvalidArgumentException('EndOfEarlyData message should have empty body, got '.strlen($payload).' bytes');
        }

        return new EndOfEarlyDataMessage();
    }
}
