<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class CustomExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private int $extensionType,
        private string $extensionData
    ) {}

    public function create(Context $context): ?Extension
    {
        return new Extension($this->extensionType, $this->extensionData);
    }

    public function getExtensionType(): int
    {
        return $this->extensionType;
    }
}