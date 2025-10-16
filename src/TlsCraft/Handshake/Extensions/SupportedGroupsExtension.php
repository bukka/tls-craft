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

    public static function decode(string $data, int &$offset = 0): self
    {
        $offset = 0;

        // Groups list length
        $groupsLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        $groups = [];
        $groupsEnd = $offset + $groupsLength;

        while ($offset < $groupsEnd) {
            $groupValue = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;

            try {
                $groups[] = NamedGroup::from($groupValue);
            } catch (\ValueError $e) {
                // Skip unknown groups
                continue;
            }
        }

        return new self($groups);
    }
}
