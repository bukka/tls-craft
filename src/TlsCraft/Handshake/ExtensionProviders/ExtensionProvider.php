<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;

interface ExtensionProvider
{
    public function create(Context $context): ?Extension;

    public function getExtensionType(): ExtensionType;
}