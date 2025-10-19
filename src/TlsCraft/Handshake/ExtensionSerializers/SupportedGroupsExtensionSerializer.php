<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\SupportedGroupsExtension;

class SupportedGroupsExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(SupportedGroupsExtension $extension): string
    {
        // Build the groups list
        $groupsData = '';
        foreach ($extension->getGroups() as $group) {
            $groupsData .= pack('n', $group->value);
        }

        // Groups list length (2 bytes)
        $groupsLength = strlen($groupsData);

        // Extension data: groups list length (2) + groups
        $extensionData = pack('n', $groupsLength) . $groupsData;

        return $this->packData($extensionData);
    }
}
