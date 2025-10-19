<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Base Extension class - now abstract
 */
abstract class Extension
{
    public function __construct(public readonly ExtensionType $type)
    {
    }
}
