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

    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }

    public function supportsAlgorithm(SignatureScheme $algorithm): bool
    {
        return in_array($algorithm, $this->signatureAlgorithms);
    }

    public function encode(): string
    {
        $algorithmsData = '';
        foreach ($this->signatureAlgorithms as $algorithm) {
            $algorithmsData .= pack('n', $algorithm->value);
        }

        return pack('n', strlen($algorithmsData)).$algorithmsData;
    }

    public static function decode(string $data): static
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;

        $algorithms = [];
        for ($i = 0; $i < $listLength; $i += 2) {
            $algorithmValue = unpack('n', substr($data, $offset + $i, 2))[1];
            $algorithms[] = SignatureScheme::from($algorithmValue);
        }

        return new self($algorithms);
    }
}
