<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Context;

class AbstractExtensionSerializer
{
    public function __construct(protected Context $context)
    {
    }

    protected function packData(string $data, string $format = 'n'): string
    {
        return pack($format, strlen($data)) . $data;
    }
}
