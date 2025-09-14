<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\Version;

class Builder
{
    private ContentType $contentType;
    private Version $version = Version::TLS_1_3;
    private string $payload = '';

    public function contentType(ContentType $type): self
    {
        $this->contentType = $type;
        return $this;
    }

    public function version(Version $version): self
    {
        $this->version = $version;
        return $this;
    }

    public function payload(string $payload): self
    {
        $this->payload = $payload;
        return $this;
    }

    public function appendPayload(string $data): self
    {
        $this->payload .= $data;
        return $this;
    }

    public function build(): Record
    {
        if (!isset($this->contentType)) {
            throw new CraftException("Content type must be set");
        }

        return new Record($this->contentType, $this->version, $this->payload);
    }

    public static function applicationData(string $data, Version $version = Version::TLS_1_3): Record
    {
        return (new self())
            ->contentType(ContentType::APPLICATION_DATA)
            ->version($version)
            ->payload($data)
            ->build();
    }

    public static function handshake(string $handshakeData, Version $version = Version::TLS_1_3): Record
    {
        return (new self())
            ->contentType(ContentType::HANDSHAKE)
            ->version($version)
            ->payload($handshakeData)
            ->build();
    }

    public static function alert(string $alertData, Version $version = Version::TLS_1_3): Record
    {
        return (new self())
            ->contentType(ContentType::ALERT)
            ->version($version)
            ->payload($alertData)
            ->build();
    }

    public static function oversized(int $size, Version $version = Version::TLS_1_3): Record
    {
        if ($size <= Record::MAX_PAYLOAD_LENGTH) {
            throw new CraftException("Size must exceed maximum payload length for oversized record");
        }

        return (new self())
            ->contentType(ContentType::APPLICATION_DATA)
            ->version($version)
            ->payload(str_repeat('A', $size))
            ->build();
    }
}