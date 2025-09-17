<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\KeyShare;
use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\KeyShareExtension;
use Php\TlsCraft\Messages\ExtensionType;

class KeyShareExtensionProvider implements ExtensionProvider
{
    public function __construct(private array $supportedGroups)
    {
    }

    public function create(Context $context): Extension
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

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::KEY_SHARE;
    }
}