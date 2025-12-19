<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\CraftException;
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
        public readonly ?string $resumptionMasterSecret = null, // For opaque tickets
        public readonly ?CipherSuite $cipherSuite = null, // For opaque tickets
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
        // For opaque tickets, check if we have the resumption secret
        if ($this->isOpaque()) {
            return $this->resumptionMasterSecret !== null && $this->cipherSuite !== null;
        }

        // For decrypted tickets, check expiry
        return !$this->data->isExpired($this->lifetime);
    }

    /**
     * Get ticket data (only for non-opaque tickets)
     *
     * @throws CraftException
     */
    public function getData(): SessionTicketData
    {
        if ($this->isOpaque()) {
            throw new CraftException('Cannot get data from opaque ticket');
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
     * Get resumption secret (works for both opaque and decrypted tickets)
     */
    public function getResumptionSecret(): string
    {
        // For opaque tickets, use the stored resumption master secret
        if ($this->isOpaque()) {
            if ($this->resumptionMasterSecret === null) {
                throw new RuntimeException('Opaque ticket missing resumption master secret');
            }

            return $this->resumptionMasterSecret;
        }

        // For decrypted tickets, use the secret from ticket data
        return $this->getData()->resumptionSecret;
    }

    /**
     * Get cipher suite (works for both opaque and decrypted tickets)
     */
    public function getCipherSuite(): CipherSuite
    {
        // For opaque tickets, use the stored cipher suite
        if ($this->isOpaque()) {
            if ($this->cipherSuite === null) {
                throw new RuntimeException('Opaque ticket missing cipher suite');
            }

            return $this->cipherSuite;
        }

        // For decrypted tickets, use cipher suite from ticket data
        return $this->getData()->cipherSuite;
    }

    /**
     * Check if ticket has expired
     */
    public function isExpired(): bool
    {
        // For opaque tickets, we can't determine expiry without server
        // Let the server validate it
        if ($this->isOpaque()) {
            return false;
        }

        return $this->getData()->isExpired($this->lifetime);
    }

    /**
     * Get ticket age for PSK identity (in milliseconds)
     */
    public function getTicketAge(): int
    {
        if ($this->isOpaque()) {
            // Use current time - ticket must have been created recently
            // This is a simplification - ideally we'd store creation timestamp
            return 0;
        }

        $age = time() - $this->getData()->timestamp;

        return $age * 1000; // Convert to milliseconds
    }
}
