<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\ExtensionType;

class SignatureAlgorithmsProvider implements ExtensionProvider
{
    public function __construct(
        private array $signatureAlgorithms,
    ) {
    }

    public function create(Context $context): ?Extension
    {
        return new SignatureAlgorithmsExtension(array_map(
            fn ($sigAlg) => SignatureScheme::fromName($sigAlg),
            $this->signatureAlgorithms,
        ));
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::SIGNATURE_ALGORITHMS;
    }
}
