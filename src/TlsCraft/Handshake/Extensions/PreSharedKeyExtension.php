<?php

namespace Php\TlsCraft\Handshake\Extensions;

use InvalidArgumentException;
use Php\TlsCraft\Crypto\PskIdentity;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * PreSharedKey Extension (RFC 8446 Section 4.2.11)
 *
 * Used in ClientHello and ServerHello
 * - ClientHello: Contains offered identities and binders
 * - ServerHello: Contains selected identity index
 *
 * MUST be the last extension in ClientHello
 */
class PreSharedKeyExtension extends Extension
{
    /**
     * @param PskIdentity[] $identities       - Client offered identities
     * @param string[]      $binders          - PSK binders (one per identity)
     * @param int|null      $selectedIdentity - Server selected identity index (ServerHello only)
     */
    public function __construct(
        public readonly array $identities = [],
        public readonly array $binders = [],
        public readonly ?int $selectedIdentity = null,
    ) {
        parent::__construct(ExtensionType::PRE_SHARED_KEY);
    }

    /**
     * Create client extension with identities (binders calculated separately)
     *
     * @param PskIdentity[] $identities
     */
    public static function forClient(array $identities): self
    {
        return new self(identities: $identities);
    }

    /**
     * Create client extension with identities and binders
     *
     * @param PskIdentity[] $identities
     * @param string[]      $binders
     */
    public static function forClientWithBinders(array $identities, array $binders): self
    {
        if (count($identities) !== count($binders)) {
            throw new InvalidArgumentException('Number of identities must match number of binders');
        }

        return new self(identities: $identities, binders: $binders);
    }

    /**
     * Create server extension with selected identity
     */
    public static function forServer(int $selectedIdentity): self
    {
        return new self(selectedIdentity: $selectedIdentity);
    }

    /**
     * Check if this is a client extension
     */
    public function isClientExtension(): bool
    {
        return !empty($this->identities);
    }

    /**
     * Check if this is a server extension
     */
    public function isServerExtension(): bool
    {
        return $this->selectedIdentity !== null;
    }

    /**
     * Get identity count
     */
    public function getIdentityCount(): int
    {
        return count($this->identities);
    }

    /**
     * Check if binders are present
     */
    public function hasBinders(): bool
    {
        return !empty($this->binders);
    }
}
