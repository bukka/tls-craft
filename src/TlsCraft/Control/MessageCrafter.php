<?php

namespace Php\TlsCraft\Control;

use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\HandshakeType;

class MessageCrafter
{
    public static function createKeyUpdate(bool $requestUpdate = false): string
    {
        $requestByte = $requestUpdate ? "\x01" : "\x00";
        $length = "\x00\x00\x01"; // 1 byte payload

        return HandshakeType::KEY_UPDATE->toByte().$length.$requestByte;
    }

    public static function createAlert(AlertLevel $level, AlertDescription $description): string
    {
        return $level->toByte().$description->toByte();
    }

    public static function createMalformedClientHello(): string
    {
        $handshakeType = HandshakeType::CLIENT_HELLO->toByte();
        $length = "\x00\x00\xFF"; // Invalid length
        $malformedData = str_repeat("\x00", 10); // Insufficient data

        return $handshakeType.$length.$malformedData;
    }

    public static function createOversizedHandshake(): string
    {
        $handshakeType = HandshakeType::CLIENT_HELLO->toByte();
        $data = str_repeat('A', 20000); // Way too large
        $length = pack('N', strlen($data));
        $length = substr($length, 1); // Remove first byte to get 3-byte length

        return $handshakeType.$length.$data;
    }

    public static function createFragmentedHandshake(string $handshakeMessage, int $fragments): array
    {
        $fragmentSize = ceil(strlen($handshakeMessage) / $fragments);
        $result = [];

        for ($i = 0; $i < $fragments; ++$i) {
            $start = $i * $fragmentSize;
            $fragment = substr($handshakeMessage, $start, $fragmentSize);
            if ($fragment !== '') {
                $result[] = $fragment;
            }
        }

        return $result;
    }
}
