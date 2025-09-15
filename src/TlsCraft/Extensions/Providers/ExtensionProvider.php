<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

interface ExtensionProvider
{
    public function create(Context $context): ?Extension;

    public function getExtensionType(): int;
}