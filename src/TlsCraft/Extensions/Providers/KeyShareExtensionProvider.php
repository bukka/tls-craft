<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class KeyShareExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private array $supportedGroups = ['P-256', 'P-384']
    ) {}

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            return $this->createClientKeyShare($context);
        } else {
            return $this->createServerKeyShare($context);
        }
    }

    public function getExtensionType(): int
    {
        return 51;
    }

    private function createClientKeyShare(Context $context): Extension
    {
        $keyShares = '';

        // For now, just include one key share for P-256
        $groupId = 0x0017; // secp256r1 (P-256)
        $publicKey = $context->getOwnPublicKeyPoint() ?? str_repeat("\x01", 65); // Placeholder

        $keyShares .= pack('n', $groupId); // group
        $keyShares .= pack('n', strlen($publicKey)); // key_exchange length
        $keyShares .= $publicKey;

        $data = pack('n', strlen($keyShares)) . $keyShares; // client_shares length + shares

        return new Extension(51, $data);
    }

    private function createServerKeyShare(Context $context): Extension
    {
        // Server sends single KeyShareEntry
        $groupId = 0x0017; // secp256r1 (P-256) - should match negotiated group
        $publicKey = $context->getOwnPublicKeyPoint() ?? str_repeat("\x02", 65); // Placeholder

        $data = pack('n', $groupId) . // group
            pack('n', strlen($publicKey)) . // key_exchange length
            $publicKey;

        return new Extension(51, $data);
    }
}