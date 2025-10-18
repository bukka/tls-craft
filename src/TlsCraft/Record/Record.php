<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class Record
{
    public const MAX_PAYLOAD_LENGTH = 16384; // 2^14 bytes
    public const HEADER_LENGTH = 5;

    public function __construct(
        public readonly ContentType $contentType,
        public readonly Version $version,
        public readonly string $payload,
        private readonly bool $encrypted = true,
    ) {
        if (strlen($payload) > self::MAX_PAYLOAD_LENGTH) {
            throw new ProtocolViolationException('Record payload too large: '.strlen($payload).' bytes');
        }
    }

    public function serialize(): string
    {
        $length = strlen($this->payload);

        return $this->contentType->toByte().
            $this->version->toBytes().
            pack('n', $length).
            $this->payload;
    }

    public static function parse(string $data, int &$offset = 0): self
    {
        if (strlen($data) - $offset < self::HEADER_LENGTH) {
            throw new CraftException('Insufficient data for TLS record header');
        }

        $contentType = ContentType::fromByte($data[$offset]);
        $version = Version::fromBytes(substr($data, $offset + 1, 2));
        $length = unpack('n', substr($data, $offset + 3, 2))[1];

        $offset += self::HEADER_LENGTH;

        if (strlen($data) - $offset < $length) {
            throw new CraftException('Insufficient data for TLS record payload');
        }

        $payload = substr($data, $offset, $length);
        $offset += $length;

        return new self($contentType, $version, $payload);
    }

    public function getLength(): int
    {
        return strlen($this->payload);
    }

    public function getTotalLength(): int
    {
        return self::HEADER_LENGTH + $this->getLength();
    }

    public function fragment(int $maxFragmentSize): array
    {
        if ($this->getLength() <= $maxFragmentSize) {
            return [$this];
        }

        $fragments = [];
        $offset = 0;
        $payloadLength = $this->getLength();

        while ($offset < $payloadLength) {
            $fragmentSize = min($maxFragmentSize, $payloadLength - $offset);
            $fragmentPayload = substr($this->payload, $offset, $fragmentSize);

            $fragments[] = new self(
                $this->contentType,
                $this->version,
                $fragmentPayload,
            );

            $offset += $fragmentSize;
        }

        return $fragments;
    }

    public function withPayload(string $newPayload): self
    {
        return new self($this->contentType, $this->version, $newPayload);
    }

    public function withCorruption(int $bytePosition, int $newValue): self
    {
        if ($bytePosition >= strlen($this->payload)) {
            throw new CraftException('Corruption position beyond payload length');
        }

        $corruptedPayload = $this->payload;
        $corruptedPayload[$bytePosition] = chr($newValue);

        return new self($this->contentType, $this->version, $corruptedPayload);
    }

    /**
     * Check if this is a handshake record
     */
    public function isHandshake(): bool
    {
        return $this->contentType === ContentType::HANDSHAKE;
    }

    /**
     * Check if this is an encrypted record
     */
    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    /**
     * Check if this is an alert record
     */
    public function isAlert(): bool
    {
        return $this->contentType === ContentType::ALERT;
    }

    /**
     * Check if this is application data
     */
    public function isApplicationData(): bool
    {
        return $this->contentType === ContentType::APPLICATION_DATA;
    }
}
