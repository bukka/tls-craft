<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Messages\ExtensionType;

interface ExtensionProvider
{
    public function create(Context $context): Extension;

    public function getExtensionType(): ExtensionType;
}