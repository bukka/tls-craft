<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\PskIdentity;
use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Provider for PreSharedKey extension
 *
 * Note: This provider creates the extension WITHOUT binders.
 * Binders must be calculated separately after the full ClientHello
 * (minus binders) is serialized.
 */
class PreSharedKeyExtensionProvider implements ExtensionProvider
{
    /**
     * @param PskIdentity[] $identities
     */
    public function __construct(
        private readonly array $identities,
    ) {
    }

    public function create(Context $context): ?PreSharedKeyExtension
    {
        if (empty($this->identities)) {
            return null;
        }

        // Return extension without binders
        // Binders will be added later during ClientHello construction
        return PreSharedKeyExtension::forClient($this->identities);
    }

    /**
     * Check if this provider has identities to offer
     */
    public function hasIdentities(): bool
    {
        return !empty($this->identities);
    }

    /**
     * Get identity count
     */
    public function getIdentityCount(): int
    {
        return count($this->identities);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::PRE_SHARED_KEY;
    }
}
