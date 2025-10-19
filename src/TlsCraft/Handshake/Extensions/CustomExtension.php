<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Custom (currently not implemented) Extension - fallback
 */
class CustomExtension extends Extension
{
    public function __construct(
        ExtensionType $type,
        private string $rawData,
    ) {
        parent::__construct($type);
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }
}
