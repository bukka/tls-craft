<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Messages\ExtensionType;

/**
 * Unknown/Unsupported Extension - fallback
 */
class UnknownExtension extends Extension
{
    public function __construct(
        ExtensionType $type,
        private string $rawData
    ) {
        parent::__construct($type);
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    public function encode(): string
    {
        return $this->rawData;
    }

    public static function decode(string $data, ExtensionType $type): static
    {
        return new self($type, $data);
    }
}
