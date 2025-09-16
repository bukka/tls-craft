<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Messages\ExtensionType;

/**
 * Supported Groups Extension
 */
class SupportedGroupsExtension extends Extension
{
    public function __construct(
        private array $groups // Array of group names/identifiers
    )
    {
        parent::__construct(ExtensionType::SUPPORTED_GROUPS);
    }

    public function getGroups(): array
    {
        return $this->groups;
    }

    public function supportsGroup(string $group): bool
    {
        return in_array($group, $this->groups);
    }

    public function encode(): string
    {
        $groupsData = '';
        foreach ($this->groups as $group) {
            // Convert group name to numeric ID (implementation specific)
            $groupId = $this->groupNameToId($group);
            $groupsData .= pack('n', $groupId);
        }
        return pack('n', strlen($groupsData)) . $groupsData;
    }

    public static function decode(string $data): static
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;

        $groups = [];
        for ($i = 0; $i < $listLength; $i += 2) {
            $groupId = unpack('n', substr($data, $offset + $i, 2))[1];
            $groups[] = self::groupIdToName($groupId);
        }

        return new self($groups);
    }

    private function groupNameToId(string $group): int
    {
        return match ($group) {
            'P-256' => 23,
            'P-384' => 24,
            'P-521' => 25,
            'X25519' => 29,
            'X448' => 30,
            default => throw new CraftException("Unknown group: {$group}")
        };
    }

    private static function groupIdToName(int $groupId): string
    {
        return match ($groupId) {
            23 => 'P-256',
            24 => 'P-384',
            25 => 'P-521',
            29 => 'X25519',
            30 => 'X448',
            default => "unknown_{$groupId}"
        };
    }
}
