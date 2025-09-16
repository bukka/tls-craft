<?php

namespace Php\TlsCraft\Messages;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ServerHello extends Message
{
    public function __construct(
        public readonly Version     $version,
        public readonly string      $random, // 32 bytes
        public readonly string      $sessionId,
        public readonly CipherSuite $cipherSuite,
        public readonly int         $compressionMethod,
        array                       $extensions // array of Extension
    )
    {
        parent::__construct(HandshakeType::SERVER_HELLO, $extensions);

        if (strlen($random) !== 32) {
            throw new ProtocolViolationException("ServerHello random must be 32 bytes");
        }
    }

    public function encode(): string
    {
        $encoded = $this->version->toBytes();
        $encoded .= $this->random;

        // Session ID
        $encoded .= chr(strlen($this->sessionId)) . $this->sessionId;

        // Cipher suite (2 bytes)
        $encoded .= pack('n', $this->cipherSuite->value);

        // Compression method (1 byte)
        $encoded .= chr($this->compressionMethod);

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

        // Cipher suite (2 bytes)
        $cipherSuite = CipherSuite::from(unpack('n', substr($data, $offset, 2))[1]);
        $offset += 2;

        // Compression method (1 byte)
        $compressionMethod = ord($data[$offset]);
        $offset++;

        // Extensions
        $extensions = Extension::decodeList($data, $offset);

        return new self($version, $random, $sessionId, $cipherSuite, $compressionMethod, $extensions);
    }
}