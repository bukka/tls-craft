<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

interface ExtensionProvider
{
    public function create(Context $context): Extension;
}