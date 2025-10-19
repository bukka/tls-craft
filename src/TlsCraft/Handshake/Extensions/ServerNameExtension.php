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
}
