<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\CustomExtension;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Messages\ExtensionType;

class CustomExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private readonly int    $extensionType,
        private readonly string $extensionData
    )
    {
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