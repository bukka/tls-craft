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

    /**
     * Calculate the total length of the binders section
     * This is used to strip binders from ClientHello for binder calculation
     *
     * @param int|null $binderLength Optional override for binder length (hash output size)
     *
     * @return int Total bytes occupied by binders section
     */
    public function getBindersLength(?int $binderLength = null): int
    {
        if (empty($this->binders)) {
            // If no binders yet, estimate based on identity count
            $binderLength = $binderLength ?? 32; // Default SHA256
            $identityCount = count($this->identities);
            $singleBinderSize = 1 + $binderLength; // 1 byte length + hash output

            return 2 + ($identityCount * $singleBinderSize); // 2 byte length prefix + binders
        }

        // Calculate actual size from existing binders
        $totalSize = 2; // 2-byte length prefix
        foreach ($this->binders as $binder) {
            $totalSize += 1 + strlen($binder); // 1 byte length + binder data
        }

        return $totalSize;
    }

    /**
     * Strip binders section from serialized ClientHello
     * Returns ClientHello with binders truncated for binder calculation
     */
    public function stripBindersFromClientHello(string $clientHelloWithHeader, ?int $binderLength = null): string
    {
        $bindersLength = $this->getBindersLength($binderLength);

        return substr($clientHelloWithHeader, 0, -$bindersLength);
    }

    public function getBinderLength(array $offeredPsks): int
    {
        if (!empty($offeredPsks)) {
            return $offeredPsks[0]->cipherSuite->getHashLength();
        }

        return 32; // Default to SHA256
    }
}
