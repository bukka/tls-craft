<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Protocol\Version;

/**
 * Supported Versions Extension
 */
class SupportedVersionsExtension extends Extension
{
    /**
     * @param Version[] $versions
     */
    public function __construct(private readonly array $versions)
    {
        parent::__construct(ExtensionType::SUPPORTED_VERSIONS);
    }

    public function getVersions(): array
    {
        return $this->versions;
    }

    public function supportsVersion(Version $version): bool
    {
        return in_array($version, $this->versions);
    }
}
