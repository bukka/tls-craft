<?php

namespace Php\TlsCraft\Session;

/**
 * PSK Identity - represents a pre-shared key identity offered by client
 */
class PskIdentity
{
    public function __construct(
        public readonly string $identity,
        public readonly int $obfuscatedTicketAge,
    ) {
    }

    /**
     * Create PSK identity from a session ticket
     */
    public static function fromTicket(string $ticket, int $ticketAgeAdd, int $ticketTimestamp): self
    {
        $age = (time() - $ticketTimestamp) * 1000; // milliseconds
        $obfuscatedAge = ($age + $ticketAgeAdd) & 0xFFFFFFFF; // mod 2^32

        return new self($ticket, $obfuscatedAge);
    }

    /**
     * Create PSK identity with zero age (for external PSKs)
     */
    public static function external(string $identity): self
    {
        return new self($identity, 0);
    }

    public function getLength(): int
    {
        return strlen($this->identity);
    }
}
