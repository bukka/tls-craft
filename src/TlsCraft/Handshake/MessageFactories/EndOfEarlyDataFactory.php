<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;

/**
 * Factory for EndOfEarlyData messages
 */
class EndOfEarlyDataFactory extends AbstractMessageFactory
{
    /**
     * Create a new EndOfEarlyData message
     */
    public function create(): EndOfEarlyDataMessage
    {
        return EndOfEarlyDataMessage::create();
    }
}
