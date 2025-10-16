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
        private array $groups
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

    public function encode(): string
    {
        // Build the groups list
        $groupsData = '';
        foreach ($this->groups as $group) {
            $groupsData .= pack('n', $group->value);
        }

        // Groups list length (2 bytes)
        $groupsLength = strlen($groupsData);

        // Extension data: groups list length (2) + groups
        $extensionData = pack('n', $groupsLength) . $groupsData;

        // Extension length (2 bytes) and data
        $data = pack('n', strlen($extensionData)) . $extensionData;

        return $data;
    }
}
