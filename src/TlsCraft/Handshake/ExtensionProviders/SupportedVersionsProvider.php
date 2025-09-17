<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Protocol\Version;

class SupportedVersionsProvider implements ExtensionProvider
{
    public function __construct(
        private array $supportedVersions
    )
    {
    }

    public function create(Context $context): Extension
    {
        return new SupportedVersionsExtension(array_map(
            fn($version) => Version::fromName($version), $this->supportedVersions
        ));
    }
}