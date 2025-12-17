<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\SupportedGroupsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

class SupportedGroupsExtensionProvider implements ExtensionProvider
{
    public function __construct(private array $supportedGroups)
    {
    }

    public function create(Context $context): ?Extension
    {
        Logger::debug('SupportedGroupsExtensionProvider: Creating extension', [
            'groups' => $this->supportedGroups,
            'is_client' => $context->isClient(),
        ]);

        // Convert group names to NamedGroup enums
        $groups = array_map(
            fn ($groupName) => NamedGroup::fromName($groupName),
            $this->supportedGroups,
        );

        return new SupportedGroupsExtension($groups);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SUPPORTED_GROUPS;
    }
}
