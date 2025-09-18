<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\CustomExtension;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;

class CustomExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private readonly int $extensionType,
        private readonly string $extensionData,
    ) {
    }

    public function create(Context $context): ?Extension
    {
        return new CustomExtension(ExtensionType::from($this->extensionType), $this->extensionData);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::from($this->extensionType);
    }
}
