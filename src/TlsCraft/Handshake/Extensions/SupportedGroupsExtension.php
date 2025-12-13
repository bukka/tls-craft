<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Handshake\ExtensionType;

class SupportedGroupsExtension extends Extension
{
    /**
     * @param NamedGroup[] $groups
     */
    public function __construct(
        private array $groups,
    ) {
        parent::__construct(ExtensionType::SUPPORTED_GROUPS);
    }

    /**
     * @return NamedGroup[]
     */
    public function getGroups(): array
    {
        return $this->groups;
    }
}
