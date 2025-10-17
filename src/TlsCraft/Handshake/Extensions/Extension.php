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

    abstract public function encode(): string;

    final public function encodeWithHeader(): string
    {
        $extensionData = $this->encode();

        return pack('nn', $this->type->value, strlen($extensionData)).$extensionData;
    }

    /**
     * @param Extension[] $extensions
     */
    public static function encodeList(array $extensions): string
    {
        $encoded = '';
        foreach ($extensions as $extension) {
            $encoded .= $extension->encodeWithHeader();
        }

        return pack('n', strlen($encoded)).$encoded;
    }
}
