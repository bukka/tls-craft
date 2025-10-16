<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ExtensionParsers\{
    AlpnExtensionParser,
    CustomExtensionParser,
    KeyShareExtensionParser,
    ServerNameExtensionParser,
    SignatureAlgorithmsExtensionParser,
    SupportedGroupsExtensionParser,
    SupportedVersionsExtensionParser
};
use Php\TlsCraft\Handshake\Extensions\{
    AlpnExtension,
    CustomExtension,
    Extension,
    KeyShareExtension,
    ServerNameExtension,
    SignatureAlgorithmsExtension,
    SupportedGroupsExtension,
    SupportedVersionsExtension
};

class ExtensionFactory
{
    // Cached parser instances
    private ?AlpnExtensionParser $alpnExtensionParser = null;
    private ?KeyShareExtensionParser $keyShareExtensionParser = null;
    private ?ServerNameExtensionParser $serverNameExtensionParser = null;
    private ?SignatureAlgorithmsExtensionParser $signatureAlgorithmsExtensionParser = null;
    private ?SupportedGroupsExtensionParser $supportedGroupsExtensionParser = null;
    private ?SupportedVersionsExtensionParser $supportedVersionsExtensionParser = null;

    private function getAlpnExtensionParser(): AlpnExtensionParser
    {
        if (!$this->alpnExtensionParser) {
            $this->alpnExtensionParser = new AlpnExtensionParser();
        }
        return $this->alpnExtensionParser;
    }

    private function getKeyShareExtensionParser(): KeyShareExtensionParser
    {
        if (!$this->keyShareExtensionParser) {
            $this->keyShareExtensionParser = new KeyShareExtensionParser();
        }
        return $this->keyShareExtensionParser;
    }

    private function getServerNameExtensionParser(): ServerNameExtensionParser
    {
        if (!$this->serverNameExtensionParser) {
            $this->serverNameExtensionParser = new ServerNameExtensionParser();
        }
        return $this->serverNameExtensionParser;
    }

    private function getSignatureAlgorithmsExtensionParser(): SignatureAlgorithmsExtensionParser
    {
        if (!$this->signatureAlgorithmsExtensionParser) {
            $this->signatureAlgorithmsExtensionParser = new SignatureAlgorithmsExtensionParser();
        }
        return $this->signatureAlgorithmsExtensionParser;
    }

    private function getSupportedGroupsExtensionParser(): SupportedGroupsExtensionParser
    {
        if (!$this->supportedGroupsExtensionParser) {
            $this->supportedGroupsExtensionParser = new SupportedGroupsExtensionParser();
        }
        return $this->supportedGroupsExtensionParser;
    }

    private function getSupportedVersionsExtensionParser(): SupportedVersionsExtensionParser
    {
        if (!$this->supportedVersionsExtensionParser) {
            $this->supportedVersionsExtensionParser = new SupportedVersionsExtensionParser();
        }
        return $this->supportedVersionsExtensionParser;
    }

    /**
     * Decode a single extension from wire format
     *
     * @param string $data The raw data
     * @param int &$offset Current position in data
     * @return Extension The parsed extension
     * @throws CraftException If insufficient data
     */
    public function decodeExtensionFromWire(string $data, int &$offset = 0): Extension
    {
        if (strlen($data) - $offset < 4) {
            throw new CraftException('Insufficient data for extension');
        }

        $typeValue = unpack('n', substr($data, $offset, 2))[1];
        $length = unpack('n', substr($data, $offset + 2, 2))[1];
        $offset += 4;

        if (strlen($data) - $offset < $length) {
            throw new CraftException('Insufficient data for extension data');
        }

        $extensionData = substr($data, $offset, $length);
        $offset += $length;

        $type = ExtensionType::from($typeValue);

        return $this->createExtension($type, $extensionData);
    }

    /**
     * Create a specific extension from parsed data
     *
     * @param ExtensionType $type The extension type
     * @param string $data The extension data
     * @return Extension The created extension
     */
    private function createExtension(ExtensionType $type, string $data): Extension
    {
        return match ($type) {
            ExtensionType::SERVER_NAME => $this->createServerNameExtensionFromWire($data),
            ExtensionType::SUPPORTED_GROUPS => $this->createSupportedGroupsExtensionFromWire($data),
            ExtensionType::SIGNATURE_ALGORITHMS => $this->createSignatureAlgorithmsExtensionFromWire($data),
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => $this->createAlpnExtensionFromWire($data),
            ExtensionType::SUPPORTED_VERSIONS => $this->createSupportedVersionsExtensionFromWire($data),
            ExtensionType::KEY_SHARE => $this->createKeyShareExtensionFromWire($data),
            default => $this->createCustomExtensionFromWire($data, $type),
        };
    }

    /**
     * Decode a list of extensions from wire format
     *
     * @param string $data The raw data
     * @param int &$offset Current position in data
     * @return Extension[] Array of parsed extensions
     * @throws CraftException If insufficient data
     */
    public function decodeExtensionList(string $data, int &$offset = 0): array
    {
        if (strlen($data) - $offset < 2) {
            throw new CraftException('Insufficient data for extensions length');
        }

        $listLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        if (strlen($data) - $offset < $listLength) {
            throw new CraftException('Insufficient data for extensions');
        }

        $extensions = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $extensions[] = $this->decodeExtensionFromWire($data, $offset);
        }

        return $extensions;
    }

    // Individual extension parsing methods
    public function createAlpnExtensionFromWire(string $data): AlpnExtension
    {
        return $this->getAlpnExtensionParser()->parse($data);
    }

    public function createKeyShareExtensionFromWire(string $data): KeyShareExtension
    {
        return $this->getKeyShareExtensionParser()->parse($data);
    }

    public function createServerNameExtensionFromWire(string $data): ServerNameExtension
    {
        return $this->getServerNameExtensionParser()->parse($data);
    }

    public function createSignatureAlgorithmsExtensionFromWire(string $data): SignatureAlgorithmsExtension
    {
        return $this->getSignatureAlgorithmsExtensionParser()->parse($data);
    }

    public function createSupportedGroupsExtensionFromWire(string $data): SupportedGroupsExtension
    {
        return $this->getSupportedGroupsExtensionParser()->parse($data);
    }

    public function createSupportedVersionsExtensionFromWire(string $data): SupportedVersionsExtension
    {
        return $this->getSupportedVersionsExtensionParser()->parse($data);
    }

    // Custom extension parser (static method, no caching needed)
    public function createCustomExtensionFromWire(string $data, ExtensionType $type): CustomExtension
    {
        return CustomExtensionParser::parse($data, $type);
    }
}
