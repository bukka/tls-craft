<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\{KeyShare, NamedGroup};
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;
use Php\TlsCraft\Handshake\ExtensionType;

class KeyShareExtensionProvider implements ExtensionProvider
{
    public function __construct(private array $supportedGroups)
    {
    }

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            return $this->createClientKeyShares($context);
        } else {
            return $this->createServerKeyShare($context);
        }
    }

    private function createClientKeyShares(Context $context): Extension
    {
        $cryptoFactory = $context->getCryptoFactory();
        $keyShares = [];

        foreach ($this->supportedGroups as $groupName) {
            $group = NamedGroup::fromName($groupName);
            $keyExchange = $cryptoFactory->createKeyExchange($group);
            $keyPair = $keyExchange->generateKeyPair();
            $context->setKeyPairForGroup($group, $keyPair);
            $keyShares[] = new KeyShare($group, $keyPair->getPublicKey());
        }

        return new KeyShareExtension($keyShares);
    }

    private function createServerKeyShare(Context $context): ?Extension
    {
        // Get the selected group from the stored client key share
        $clientKeyShare = $context->getClientKeyShare();
        if (!$clientKeyShare) {
            throw new CraftException("Client key share not available for server");
        }

        $selectedGroup = $clientKeyShare->getGroup();

        // Generate server key pair for the selected group
        $cryptoFactory = $context->getCryptoFactory();
        $keyExchange = $cryptoFactory->createKeyExchange($selectedGroup);
        $serverKeyPair = $keyExchange->generateKeyPair();

        // Store server's key pair
        $context->setKeyPairForGroup($selectedGroup, $serverKeyPair);

        // Server sends only one key share (for the selected group)
        return new KeyShareExtension([
            new KeyShare($selectedGroup, $serverKeyPair->getPublicKey())
        ]);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::KEY_SHARE;
    }
}