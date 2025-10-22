<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Signature Algorithms Extension
 */
class SignatureAlgorithmsExtension extends Extension
{
    public function __construct(
        private array $signatureAlgorithms,
    ) {
        parent::__construct(ExtensionType::SIGNATURE_ALGORITHMS);
    }

    /** @return SignatureScheme[] */
    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }

    public function supportsAlgorithm(SignatureScheme $algorithm): bool
    {
        return in_array($algorithm, $this->signatureAlgorithms);
    }
}
