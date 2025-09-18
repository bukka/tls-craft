<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Base Extension class - now abstract
 */
abstract class Extension
{
    public function __construct(
        public readonly ExtensionType $type,
    ) {
    }

    abstract public function encode(): string;

    final public function encodeWithHeader(): string
    {
        $extensionData = $this->encode();

        return pack('nn', $this->type->value, strlen($extensionData)).$extensionData;
    }

    public static function decodeFromWire(string $data, int &$offset = 0): self
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

        // Factory method to create specific extension types
        return self::createExtension($type, $extensionData);
    }

    private static function createExtension(ExtensionType $type, string $data): self
    {
        return match ($type) {
            ExtensionType::SERVER_NAME => ServerNameExtension::decode($data),
            ExtensionType::SUPPORTED_VERSIONS => SupportedVersionsExtension::decode($data),
            ExtensionType::KEY_SHARE => KeyShareExtension::decode($data),
            ExtensionType::SIGNATURE_ALGORITHMS => SignatureAlgorithmsExtension::decode($data),
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => ALPNExtension::decode($data),
            ExtensionType::SUPPORTED_GROUPS => SupportedGroupsExtension::decode($data),
            default => CustomExtension::decode($data, $type),
        };
    }

    /**
     * @param Extension[] $extensions
     */
    public static function encodeList(array $extensions): string
    {
        $encoded = '';
        foreach ($extensions as $extension) {
            $encoded .= $extension->encodeWithHeader();
        }

        return pack('n', strlen($encoded)).$encoded;
    }

    public static function decodeList(string $data, int &$offset = 0): array
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
            $extensions[] = self::decodeFromWire($data, $offset);
        }

        return $extensions;
    }
}
