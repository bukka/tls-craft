<?php

namespace Php\TlsCraft\Messages;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ClientHello extends HandshakeMessage
{
    public function __construct(
        public readonly Version $version,
        public readonly string  $random, // 32 bytes
        public readonly string  $sessionId,
        public readonly array   $cipherSuites, // array of int
        public readonly array   $compressionMethods, // array of int
        public readonly array   $extensions // array of Extension
    )
    {
        parent::__construct(HandshakeType::CLIENT_HELLO);

        if (strlen($random) !== 32) {
            throw new ProtocolViolationException("ClientHello random must be 32 bytes");
        }
    }

    public function encode(): string
    {
        $encoded = $this->version->toBytes();
        $encoded .= $this->random;

        // Session ID
        $encoded .= chr(strlen($this->sessionId)) . $this->sessionId;

        // Cipher suites
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $encoded .= pack('n', strlen($cipherSuitesData)) . $cipherSuitesData;

        // Compression methods
        $compressionData = '';
        foreach ($this->compressionMethods as $method) {
            $compressionData .= chr($method);
        }
        $encoded .= chr(strlen($compressionData)) . $compressionData;

        // Extensions
        $encoded .= Extension::encodeList($this->extensions);

        return $encoded;
    }

    public static function decode(string $data): static
    {
        $offset = 0;

        // Version (2 bytes)
        $version = Version::fromBytes(substr($data, $offset, 2));
        $offset += 2;

        // Random (32 bytes)
        $random = substr($data, $offset, 32);
        $offset += 32;

        // Session ID
        $sessionIdLength = ord($data[$offset]);
        $offset++;
        $sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;

        // Cipher suites
        $cipherSuitesLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        $cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            $cipherSuites[] = unpack('n', substr($data, $offset + $i, 2))[1];
        }
        $offset += $cipherSuitesLength;

        // Compression methods
        $compressionLength = ord($data[$offset]);
        $offset++;

        $compressionMethods = [];
        for ($i = 0; $i < $compressionLength; $i++) {
            $compressionMethods[] = ord($data[$offset + $i]);
        }
        $offset += $compressionLength;

        // Extensions
        $extensions = Extension::decodeList($data, $offset);

        return new self($version, $random, $sessionId, $cipherSuites, $compressionMethods, $extensions);
    }

    public static function create(
        ?string $hostname = null,
        array   $cipherSuites = [0x1301, 0x1302, 0x1303], // TLS 1.3 suites
        array   $extensions = []
    ): self
    {
        $random = random_bytes(32);
        $sessionId = ''; // Empty for TLS 1.3
        $compressionMethods = [0]; // Null compression

        // Add SNI extension if hostname provided
        if ($hostname !== null) {
            $sniData = pack('n', strlen($hostname) + 5) . // list length
                "\x00" . // name type (hostname)
                pack('n', strlen($hostname)) .
                $hostname;
            $extensions[] = new Extension(0, $sniData); // SNI extension type = 0
        }

        // Add supported versions extension (TLS 1.3)
        $versionsData = "\x02" . Version::TLS_1_3->toBytes(); // 1 version, 2 bytes
        $extensions[] = new Extension(43, $versionsData); // supported_versions = 43

        return new self(
            Version::TLS_1_2, // Legacy version field
            $random,
            $sessionId,
            $cipherSuites,
            $compressionMethods,
            $extensions
        );
    }
}