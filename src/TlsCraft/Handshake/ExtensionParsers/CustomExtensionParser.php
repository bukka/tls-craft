<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\CustomExtension;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Custom (currently not implemented) Extension (fallback) parser
 */
class CustomExtensionParser extends AbstractExtensionParser
{
    public function parse(string $data, ExtensionType $type): CustomExtension
    {
        return new CustomExtension($type, $data);
    }
}
