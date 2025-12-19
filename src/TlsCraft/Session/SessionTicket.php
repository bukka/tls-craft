<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;
use RuntimeException;

class SessionTicket
{
    private ?string $identifier = null;

    public function __construct(
        public readonly string $ticket,
        public readonly ?SessionTicketData $data, // Null for opaque tickets
        public readonly int $lifetime,
        public readonly int $ageAdd,
        public readonly string $nonce,
        public readonly ?string $serverName = null,
    ) {
    }

    /**
     * Get unique identifier for this ticket
     * Uses hash of ticket content - works for both opaque and decrypted tickets
     */
    public function getIdentifier(): string
    {
        if ($this->identifier === null) {
            $this->identifier = hash('sha256', $this->ticket);
        }

        return $this->identifier;
    }

    /**
     * Check if this is an opaque ticket (client doesn't understand contents)
     */
    public function isOpaque(): bool
    {
        return $this->data === null;
    }

    /**
     * Check if this ticket can be used for resumption
     */
    public function isValid(): bool
    {
        // Opaque tickets are considered valid (server will validate)
        if ($this->isOpaque()) {
            return true;
        }

        // For decrypted tickets, check expiry
        return !$this->data->isExpired($this->lifetime);
    }

    /**
     * Get ticket data (only for non-opaque tickets)
     */
    public function getData(): SessionTicketData
    {
        if ($this->isOpaque()) {
            throw new RuntimeException('Cannot get data from opaque ticket');
        }

        return $this->data;
    }

    /**
     * Get server name (works for both opaque and decrypted)
     * This is the SNI hostname used for session cache lookup
     */
    public function getServerName(): ?string
    {
        // Prefer decrypted server name
        if (!$this->isOpaque()) {
            return $this->data->serverName;
        }

        // Fall back to provided server name
        return $this->serverName;
    }

    /**
     * Get resumption secret (only for non-opaque tickets)
     */
    public function getResumptionSecret(): string
    {
        return $this->getData()->resumptionSecret;
    }

    /**
     * Get cipher suite (only for non-opaque tickets)
     */
    public function getCipherSuite(): CipherSuite
    {
        return $this->getData()->cipherSuite;
    }

    /**
     * Check if ticket has expired
     */
    public function isExpired(): bool
    {
        if ($this->isOpaque()) {
            return false;
        }

        return $this->getData()->isExpired($this->lifetime);
    }
}
