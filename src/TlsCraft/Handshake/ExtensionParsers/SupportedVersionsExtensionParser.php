<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Protocol\Version;

/**
 * Supported Versions Extension parser
 */
class SupportedVersionsExtensionParser
{

    public static function parse(string $data): SupportedVersionsExtension
    {
        $listLength = ord($data[0]);
        $offset = 1;

        $versions = [];
        for ($i = 0; $i < $listLength; $i += 2) {
            $versionBytes = substr($data, $offset + $i, 2);
            $versions[] = Version::fromBytes($versionBytes);
        }

        return new SupportedVersionsExtension($versions);
    }
}
