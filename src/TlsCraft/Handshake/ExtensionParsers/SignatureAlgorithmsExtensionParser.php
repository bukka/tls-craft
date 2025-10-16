<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;

/**
 * Signature Algorithms Extension parser
 */
class SignatureAlgorithmsExtensionParser
{
    public function parse(string $data): SignatureAlgorithmsExtension
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;

        $algorithms = [];
        for ($i = 0; $i < $listLength; $i += 2) {
            $algorithmValue = unpack('n', substr($data, $offset + $i, 2))[1];
            $algorithms[] = SignatureScheme::from($algorithmValue);
        }

        return new SignatureAlgorithmsExtension($algorithms);
    }
}
