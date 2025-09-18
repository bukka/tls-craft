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

    public function encode(): string
    {
        $versionsData = '';
        foreach ($this->versions as $version) {
            $versionsData .= $version->toBytes();
        }

        return chr(strlen($versionsData)).$versionsData;
    }

    public static function decode(string $data): static
    {
        $listLength = ord($data[0]);
        $offset = 1;

        $versions = [];
        for ($i = 0; $i < $listLength; $i += 2) {
            $versionBytes = substr($data, $offset + $i, 2);
            $versions[] = Version::fromBytes($versionBytes);
        }

        return new self($versions);
    }
}
