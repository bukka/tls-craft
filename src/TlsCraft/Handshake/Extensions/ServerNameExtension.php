<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ExtensionType;

class ServerNameExtension extends Extension
{
    public function __construct(
        private string $serverName,
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
        $nameData = chr(0).pack('n', strlen($this->serverName)).$this->serverName;

        return pack('n', strlen($nameData)).$nameData;
    }
}
