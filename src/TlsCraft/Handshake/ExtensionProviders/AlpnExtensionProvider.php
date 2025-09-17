<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\AlpnExtension;
use Php\TlsCraft\Extensions\Extension;

class AlpnExtensionProvider implements ExtensionProvider
{
    public function __construct(private readonly array $protocols)
    {
    }

    public function create(Context $context): Extension
    {
        return new AlpnExtension($this->protocols);
    }
}