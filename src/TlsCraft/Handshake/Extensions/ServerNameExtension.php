<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ExtensionType;

class ServerNameExtension extends Extension
{
    public function __construct(
        private string $serverName
    ) {
        parent::__construct(ExtensionType::SERVER_NAME);
    }

    public function getServerName(): string
    {
        return $this->serverName;
    }

    public function encode(): string
    {
        // Server name list length (2 bytes)
        // Name type (1 byte) - 0 for hostname
        // Name length (2 bytes)
        // Name data
        $nameData = chr(0) . pack('n', strlen($this->serverName)) . $this->serverName;
        return pack('n', strlen($nameData)) . $nameData;
    }

    public static function decode(string $data): static
    {
        $offset = 0;

        // Server name list length
        $listLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // Name type (should be 0 for hostname)
        $nameType = ord($data[$offset]);
        $offset += 1;

        if ($nameType !== 0) {
            throw new CraftException("Unsupported name type: {$nameType}");
        }

        // Name length
        $nameLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // Server name
        $serverName = substr($data, $offset, $nameLength);

        return new self($serverName);
    }
}