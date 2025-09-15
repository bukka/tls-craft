<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class SignatureAlgorithmsProvider implements ExtensionProvider
{
    public function __construct(
        private array $signatureAlgorithms
    ) {}

    public function create(Context $context): ?Extension
    {
        // Only include in ClientHello and CertificateRequest
        if (!$context->isClient()) {
            return null;
        }

        $data = pack('n', count($this->signatureAlgorithms) * 2); // length
        foreach ($this->signatureAlgorithms as $algorithm) {
            $data .= pack('n', $algorithm);
        }

        return new Extension(13, $data); // signature_algorithms = 13
    }

    public function getExtensionType(): int
    {
        return 13;
    }
}