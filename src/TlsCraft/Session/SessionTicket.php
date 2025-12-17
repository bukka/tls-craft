<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;

/**
 * Represents a TLS 1.3 session ticket for resumption
 */
class SessionTicket
{
    public function __construct(
        public readonly string $ticket,              // Opaque ticket data
        public readonly string $resumptionSecret,    // PSK derived from this ticket
        public readonly CipherSuite $cipherSuite,    // Cipher suite for this session
        public readonly int $lifetime,               // Lifetime in seconds
        public readonly int $ageAdd,                 // Obfuscation value for ticket age
        public readonly string $nonce,               // Ticket nonce
        public readonly int $timestamp,              // When ticket was issued (Unix timestamp)
        public readonly int $maxEarlyDataSize = 0,   // Max early data size (0 = no 0-RTT)
        public readonly ?string $serverName = null,  // Server name (SNI) for this ticket
    ) {
    }

    /**
     * Check if ticket has expired
     */
    public function isExpired(): bool
    {
        return (time() - $this->timestamp) > $this->lifetime;
    }

    /**
     * Get ticket age in milliseconds
     */
    public function getAge(): int
    {
        return (time() - $this->timestamp) * 1000; // Convert to milliseconds
    }

    /**
     * Get obfuscated ticket age for PSK extension
     */
    public function getObfuscatedAge(): int
    {
        $age = $this->getAge();

        return ($age + $this->ageAdd) & 0xFFFFFFFF; // mod 2^32
    }

    /**
     * Get remaining lifetime in seconds
     */
    public function getRemainingLifetime(): int
    {
        $elapsed = time() - $this->timestamp;

        return max(0, $this->lifetime - $elapsed);
    }

    /**
     * Check if ticket supports early data (0-RTT)
     */
    public function supportsEarlyData(): bool
    {
        return $this->maxEarlyDataSize > 0;
    }

    /**
     * Get ticket identity (the ticket itself is the identity)
     */
    public function getIdentity(): string
    {
        return $this->ticket;
    }
}
