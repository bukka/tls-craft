<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\CertificateVerify;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateVerifyFactory extends AbstractMessageFactory
{
    public function create(string $signature): CertificateVerify
    {
        $signatureScheme = $this->context->getNegotiatedSignatureScheme();
        if ($signatureScheme === null) {
            throw new CraftException('No signature scheme negotiated');
        }

        return new CertificateVerify($signatureScheme, $signature);
    }

    public function fromWire(string $data): CertificateVerify
    {
        $payload = $this->parseHandshake($data, HandshakeType::CERTIFICATE_VERIFY);

        $algorithm = unpack('n', substr($payload, 0, 2))[1];
        $sigLength = unpack('n', substr($payload, 2, 2))[1];
        $signature = substr($payload, 4, $sigLength);

        return new CertificateVerify(SignatureScheme::from($algorithm), $signature);
    }
}
