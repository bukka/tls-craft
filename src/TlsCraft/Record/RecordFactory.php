<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\Version;

class RecordFactory
{
    public static function createApplicationData(
        string $data,
        Version $version = Version::TLS_1_3,
    ): Record {
        return new Record(
            ContentType::APPLICATION_DATA,
            $version,
            $data,
        );
    }

    public static function createHandshake(
        string $handshakeData,
        $encrypted = true,
        Version $version = Version::TLS_1_3,
    ): Record {
        return new Record(
            ContentType::HANDSHAKE,
            $version,
            $handshakeData,
            $encrypted,
        );
    }

    public static function createAlert(
        string $alertData,
        Version $version = Version::TLS_1_3,
    ): Record {
        return new Record(
            ContentType::ALERT,
            $version,
            $alertData,
        );
    }

    public static function createOversized(
        int $size,
        Version $version = Version::TLS_1_3,
    ): Record {
        if ($size <= Record::MAX_PAYLOAD_LENGTH) {
            throw new CraftException('Size must exceed maximum payload length for oversized record');
        }

        return new Record(
            ContentType::APPLICATION_DATA,
            $version,
            str_repeat('A', $size),
        );
    }
}
