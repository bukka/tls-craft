<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

class SignatureAlgorithmsProvider implements ExtensionProvider
{
    public function __construct(
        private array $signatureAlgorithms,
    ) {
    }

    public function create(Context $context): ?Extension
    {
        Logger::debug('SignatureAlgorithmsProvider: Creating extension', [
            'algorithms' => $this->signatureAlgorithms,
            'is_client' => $context->isClient(),
        ]);

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
