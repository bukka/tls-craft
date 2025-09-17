<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\KeyShare;
use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\KeyShareExtension;

class KeyShareExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private array $supportedGroups = ['P-256', 'P-384']
    )
    {
    }

    public function create(Context $context): Extension
    {
        return new KeyShareExtension(array_map(
            fn($supportedGroup) => KeyShare::generate(NamedGroup::fromName($supportedGroup)), $this->supportedGroups
        ));
    }
}