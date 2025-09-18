<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ClientHello extends Message
{
    public function __construct(
        public readonly Version $version,
        public readonly string  $random, // 32 bytes
        public readonly string  $sessionId,
        public readonly array   $cipherSuites, // array of int
        public readonly array   $compressionMethods, // array of int
        array                   $extensions // array of Extension
    )
    {
        parent::__construct(HandshakeType::CLIENT_HELLO, $extensions);

        if (strlen($random) !== 32) {
            throw new ProtocolViolationException("ClientHello random must be 32 bytes");
        }
    }

    public function encode(): string
    {
        $encoded = $this->version->toBytes();
        $encoded .= $this->random;

        // Session ID (length-prefixed)
        $encoded .= chr(strlen($this->sessionId)) . $this->sessionId;

        // Cipher suites (length-prefixed, 2 bytes per suite)
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $encoded .= pack('n', strlen($cipherSuitesData)) . $cipherSuitesData;

        // Compression methods (length-prefixed, 1 byte per method)
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
}