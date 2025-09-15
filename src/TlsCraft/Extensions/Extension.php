<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Exceptions\CraftException;

class Extension
{
    public function __construct(
        public readonly int    $type,
        public readonly string $data
    )
    {
    }

    public function encode(): string
    {
        return pack('n', $this->type) .
            pack('n', strlen($this->data)) .
            $this->data;
    }

    public static function decode(string $data, int &$offset = 0): self
    {
        if (strlen($data) - $offset < 4) {
            throw new CraftException("Insufficient data for extension");
        }

        $type = unpack('n', substr($data, $offset, 2))[1];
        $length = unpack('n', substr($data, $offset + 2, 2))[1];
        $offset += 4;

        if (strlen($data) - $offset < $length) {
            throw new CraftException("Insufficient data for extension data");
        }

        $extensionData = substr($data, $offset, $length);
        $offset += $length;

        return new self($type, $extensionData);
    }

    public static function encodeList(array $extensions): string
    {
        $encoded = '';
        foreach ($extensions as $extension) {
            $encoded .= $extension->encode();
        }

        return pack('n', strlen($encoded)) . $encoded;
    }

    public static function decodeList(string $data, int &$offset = 0): array
    {
        if (strlen($data) - $offset < 2) {
            throw new CraftException("Insufficient data for extensions length");
        }

        $listLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        if (strlen($data) - $offset < $listLength) {
            throw new CraftException("Insufficient data for extensions");
        }

        $extensions = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $extensions[] = self::decode($data, $offset);
        }

        return $extensions;
    }
}