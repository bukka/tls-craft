<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Protocol\Version;

/**
 * Supported Versions Extension parser
 */
class SupportedVersionsExtensionParser extends AbstractExtensionParser
{
    public function parse(string $data): SupportedVersionsExtension
    {
        $versions = [];

        if ($this->context->isClient()) {
            // ServerHelloMessage format: must be exactly a single 2-byte version (no length prefix)
            if (strlen($data) !== 2) {
                throw new CraftException(sprintf('Invalid SupportedVersions extension in ServerHelloMessage: expected 2 bytes, got %d', strlen($data)));
            }
            $versions[] = Version::fromBytes($data);
        } else {
            // ClientHelloMessage format: 1-byte length followed by list of 2-byte versions
            $listLength = ord($data[0]);
            $offset = 1;

            for ($i = 0; $i < $listLength; $i += 2) {
                $versionBytes = substr($data, $offset + $i, 2);
                $versions[] = Version::fromBytes($versionBytes);
            }
        }

        return new SupportedVersionsExtension($versions);
    }
}
