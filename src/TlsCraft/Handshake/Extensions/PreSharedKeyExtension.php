<?php

namespace Php\TlsCraft\Handshake\Extensions;

use InvalidArgumentException;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Session\PskIdentity;

/**
 * PreSharedKey Extension (RFC 8446 Section 4.2.11)
 */
class PreSharedKeyExtension extends Extension
{
    /**
     * @param PskIdentity[] $identities
     * @param string[]      $binders
     */
    public function __construct(
        public readonly array $identities = [],
        public array $binders = [],  // Changed from readonly to allow setting
        public readonly ?int $selectedIdentity = null,
    ) {
        parent::__construct(ExtensionType::PRE_SHARED_KEY);
    }

    /**
     * Create client extension with identities (binders will be calculated later)
     */
    public static function forClient(array $identities): self
    {
        return new self(identities: $identities);
    }

    /**
     * Create client extension with identities and binders
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
     * Set binders (called after calculation)
     */
    public function setBinders(array $binders): void
    {
        if (count($this->identities) !== count($binders)) {
            throw new InvalidArgumentException('Number of binders must match number of identities');
        }

        $this->binders = $binders;
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
