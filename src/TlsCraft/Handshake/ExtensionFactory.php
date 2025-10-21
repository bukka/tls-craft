<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Context;
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
use Php\TlsCraft\Handshake\ExtensionSerializers\{
    AlpnExtensionSerializer,
    CustomExtensionSerializer,
    KeyShareExtensionSerializer,
    ServerNameExtensionSerializer,
    SignatureAlgorithmsExtensionSerializer,
    SupportedGroupsExtensionSerializer,
    SupportedVersionsExtensionSerializer
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
    /** ------------------------------- PARSERS -------------------------------- */
    private ?AlpnExtensionParser $alpnExtensionParser = null;
    private ?CustomExtensionParser $customExtensionParser = null;
    private ?KeyShareExtensionParser $keyShareExtensionParser = null;
    private ?ServerNameExtensionParser $serverNameExtensionParser = null;
    private ?SignatureAlgorithmsExtensionParser $signatureAlgorithmsExtensionParser = null;
    private ?SupportedGroupsExtensionParser $supportedGroupsExtensionParser = null;
    private ?SupportedVersionsExtensionParser $supportedVersionsExtensionParser = null;

    /** ----------------------------- SERIALIZERS ------------------------------ */
    private ?AlpnExtensionSerializer $alpnExtensionSerializer = null;
    private ?CustomExtensionSerializer $customExtensionSerializer = null;
    private ?KeyShareExtensionSerializer $keyShareExtensionSerializer = null;
    private ?ServerNameExtensionSerializer $serverNameExtensionSerializer = null;
    private ?SignatureAlgorithmsExtensionSerializer $signatureAlgorithmsExtensionSerializer = null;
    private ?SupportedGroupsExtensionSerializer $supportedGroupsExtensionSerializer = null;
    private ?SupportedVersionsExtensionSerializer $supportedVersionsExtensionSerializer = null;

    public function __construct(private Context $context) {}

    /* ============================== Parsers ============================== */

    private function getAlpnExtensionParser(): AlpnExtensionParser
    {
        return $this->alpnExtensionParser ??= new AlpnExtensionParser($this->context);
    }


    private function getCustomExtensionParser(): CustomExtensionParser
    {
        return $this->customExtensionParser ??= new CustomExtensionParser($this->context);
    }

    private function getKeyShareExtensionParser(): KeyShareExtensionParser
    {
        return $this->keyShareExtensionParser ??= new KeyShareExtensionParser($this->context);
    }

    private function getServerNameExtensionParser(): ServerNameExtensionParser
    {
        return $this->serverNameExtensionParser ??= new ServerNameExtensionParser($this->context);
    }

    private function getSignatureAlgorithmsExtensionParser(): SignatureAlgorithmsExtensionParser
    {
        return $this->signatureAlgorithmsExtensionParser ??= new SignatureAlgorithmsExtensionParser($this->context);
    }

    private function getSupportedGroupsExtensionParser(): SupportedGroupsExtensionParser
    {
        return $this->supportedGroupsExtensionParser ??= new SupportedGroupsExtensionParser($this->context);
    }

    private function getSupportedVersionsExtensionParser(): SupportedVersionsExtensionParser
    {
        return $this->supportedVersionsExtensionParser ??= new SupportedVersionsExtensionParser($this->context);
    }

    /* ============================ Serializers ============================ */

    private function getAlpnExtensionSerializer(): AlpnExtensionSerializer
    {
        return $this->alpnExtensionSerializer ??= new AlpnExtensionSerializer($this->context);
    }

    private function getCustomExtensionSerializer(): CustomExtensionSerializer
    {
        return $this->customExtensionSerializer ??= new CustomExtensionSerializer($this->context);
    }

    private function getKeyShareExtensionSerializer(): KeyShareExtensionSerializer
    {
        return $this->keyShareExtensionSerializer ??= new KeyShareExtensionSerializer($this->context);
    }

    private function getServerNameExtensionSerializer(): ServerNameExtensionSerializer
    {
        return $this->serverNameExtensionSerializer ??= new ServerNameExtensionSerializer($this->context);
    }

    private function getSignatureAlgorithmsExtensionSerializer(): SignatureAlgorithmsExtensionSerializer
    {
        return $this->signatureAlgorithmsExtensionSerializer ??= new SignatureAlgorithmsExtensionSerializer($this->context);
    }

    private function getSupportedGroupsExtensionSerializer(): SupportedGroupsExtensionSerializer
    {
        return $this->supportedGroupsExtensionSerializer ??= new SupportedGroupsExtensionSerializer($this->context);
    }

    private function getSupportedVersionsExtensionSerializer(): SupportedVersionsExtensionSerializer
    {
        return $this->supportedVersionsExtensionSerializer ??= new SupportedVersionsExtensionSerializer($this->context);
    }

    /** ============================ Decoding path ============================ */

    public function decodeExtensionFromWire(string $data, int &$offset = 0): Extension
    {
        if (strlen($data) - $offset < 4) {
            throw new CraftException('Insufficient data for extension');
        }

        $typeValue = unpack('n', substr($data, $offset, 2))[1];
        $length    = unpack('n', substr($data, $offset + 2, 2))[1];
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
     * @return Extension[]
     * @throws CraftException
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

    private function createExtension(ExtensionType $type, string $data): Extension
    {
        return match ($type) {
            ExtensionType::SERVER_NAME                   => $this->getServerNameExtensionParser()->parse($data),
            ExtensionType::SUPPORTED_GROUPS              => $this->getSupportedGroupsExtensionParser()->parse($data),
            ExtensionType::SIGNATURE_ALGORITHMS          => $this->getSignatureAlgorithmsExtensionParser()->parse($data),
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            => $this->getAlpnExtensionParser()->parse($data),
            ExtensionType::SUPPORTED_VERSIONS            => $this->getSupportedVersionsExtensionParser()->parse($data),
            ExtensionType::KEY_SHARE                     => $this->getKeyShareExtensionParser()->parse($data),
            default                                      => $this->getCustomExtensionParser()->parse($data, $type),
        };
    }

    /** ============================ Encoding path ============================ */
    /**
     * Encode a list of extensions with the proper length prefix (RFC 8446 §4.2).
     * Uses per-type, strongly-typed serializers.
     *
     * @param Extension[] $extensions
     */
    public function encodeExtensionList(array $extensions): string
    {
        $blob = '';
        foreach ($extensions as $ext) {
            $blob .= $this->encodeExtensionWithHeader($ext);
        }
        return pack('n', strlen($blob)) . $blob;
    }

    /**
     * Encode a single extension including its 4-byte header (type + length).
     */
    public function encodeExtensionWithHeader(Extension $ext): string
    {
        $body = $this->serializeExtensionBody($ext);
        return pack('nn', $ext->type->value, strlen($body)) . $body;
    }

    /**
     * Serialize only the extension body (no header) via a strongly-typed serializer.
     */
    public function serializeExtensionBody(Extension $ext): string
    {
        return match (true) {
            $ext instanceof AlpnExtension                => $this->getAlpnExtensionSerializer()->serialize($ext),
            $ext instanceof KeyShareExtension            => $this->getKeyShareExtensionSerializer()->serialize($ext),
            $ext instanceof ServerNameExtension          => $this->getServerNameExtensionSerializer()->serialize($ext),
            $ext instanceof SignatureAlgorithmsExtension => $this->getSignatureAlgorithmsExtensionSerializer()->serialize($ext),
            $ext instanceof SupportedGroupsExtension     => $this->getSupportedGroupsExtensionSerializer()->serialize($ext),
            $ext instanceof SupportedVersionsExtension   => $this->getSupportedVersionsExtensionSerializer()->serialize($ext),
            $ext instanceof CustomExtension              => $this->getCustomExtensionSerializer()->serialize($ext),
            default => throw new CraftException('No serializer available for extension type: ' . $ext::class),
        };
    }
}
