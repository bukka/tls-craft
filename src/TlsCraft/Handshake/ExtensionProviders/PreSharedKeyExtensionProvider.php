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
    public function create(Context $context): ?PreSharedKeyExtension
    {
        // Collect PSK identities from context
        $offeredPsks = $context->getOfferedPsks();

        if (empty($offeredPsks)) {
            // No PSKs available
            return null;
        }

        // Build identity array from PSKs
        $identities = [];
        foreach ($offeredPsks as $psk) {
            if ($psk->identity === $psk->identity) { // Session ticket
                // Create identity from ticket
                $identities[] = PskIdentity::fromTicket(
                    $psk->identity,
                    0, // ageAdd - will be set from ticket metadata
                    time(), // timestamp - will be set from ticket metadata
                );
            } else {
                // External PSK
                $identities[] = PskIdentity::external($psk->identity);
            }
        }

        // Return extension without binders
        // Binders will be added later during ClientHello construction
        return PreSharedKeyExtension::forClient($identities);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::PRE_SHARED_KEY;
    }
}
