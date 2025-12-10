<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\CustomExtension;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

class CustomExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private readonly int $extensionType,
        private readonly string $extensionData,
    ) {
    }

    public function create(Context $context): ?Extension
    {
        Logger::debug('CustomExtensionProvider: Creating custom extension', [
            'extension_type' => $this->extensionType,
            'data_length' => strlen($this->extensionData),
            'data_hex' => bin2hex($this->extensionData),
        ]);

        return new CustomExtension(ExtensionType::from($this->extensionType), $this->extensionData);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::from($this->extensionType);
    }
}
