<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;

/**
 * Pre-Shared Key (PSK) - contains the secret and metadata
 */
class PreSharedKey
{
    private ?int $ticketAgeAdd = null;
    private ?int $ticketTimestamp = null;

    public function __construct(
        public readonly string $identity,
        public readonly string $secret,
        public readonly CipherSuite $cipherSuite,
        public readonly int $maxEarlyDataSize = 0,
    ) {
    }

    /**
     * Create PSK from a session ticket
     * Works for both opaque and decrypted tickets
     */
    public static function fromSessionTicket(SessionTicket $ticket): self
    {
        $psk = new self(
            identity: $ticket->ticket,
            secret: $ticket->getResumptionSecret(),
            cipherSuite: $ticket->getCipherSuite(),
            maxEarlyDataSize: $ticket->getMaxEarlyDataSize(),
        );

        // Store metadata needed for obfuscated ticket age calculation
        $psk->ticketAgeAdd = $ticket->ageAdd;
        $psk->ticketTimestamp = $ticket->getTimestamp();

        return $psk;
    }

    /**
     * Create external PSK (manually configured, not from ticket)
     */
    public static function external(
        string $identity,
        string $secret,
        CipherSuite $cipherSuite,
    ): self {
        return new self($identity, $secret, $cipherSuite);
    }

    /**
     * Check if this is a resumption PSK (from session ticket)
     */
    public function isResumption(): bool
    {
        return $this->ticketTimestamp !== null;
    }

    /**
     * Get ticket age add value (for resumption PSKs)
     */
    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd ?? 0;
    }

    /**
     * Get ticket timestamp (for resumption PSKs)
     */
    public function getTicketTimestamp(): int
    {
        return $this->ticketTimestamp ?? 0;
    }

    /**
     * Get hash algorithm for this PSK based on cipher suite
     */
    public function getHashAlgorithm(): string
    {
        return $this->cipherSuite->getHashAlgorithm();
    }

    /**
     * Get hash length in bytes
     */
    public function getHashLength(): int
    {
        return $this->cipherSuite->getHashLength();
    }
}
