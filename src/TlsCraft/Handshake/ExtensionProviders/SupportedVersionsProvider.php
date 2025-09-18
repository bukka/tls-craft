<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Protocol\Version;

class SupportedVersionsProvider implements ExtensionProvider
{
    public function __construct(
        private array $supportedVersions
    )
    {
    }

    public function create(Context $context): ?Extension
    {
        return new SupportedVersionsExtension(array_map(
            fn($version) => Version::fromName($version), $this->supportedVersions
        ));
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SUPPORTED_VERSIONS;
    }
}