<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Extensions\SignatureAlgorithmsExtension;

class SignatureAlgorithmsProvider implements ExtensionProvider
{
    public function __construct(
        private array $signatureAlgorithms
    )
    {
    }

    public function create(Context $context): Extension
    {
        return new SignatureAlgorithmsExtension(array_map(
            fn($sigAlg) => SignatureScheme::fromName($sigAlg), $this->signatureAlgorithms
        ));
    }
}