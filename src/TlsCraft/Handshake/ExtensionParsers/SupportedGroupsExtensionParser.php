<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Handshake\Extensions\SupportedGroupsExtension;
use ValueError;

class SupportedGroupsExtensionParser extends AbstractExtensionParser
{
    public function parse(string $data, int &$offset = 0): SupportedGroupsExtension
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
            } catch (ValueError $e) {
                // Skip unknown groups
                continue;
            }
        }

        return new SupportedGroupsExtension($groups);
    }
}
