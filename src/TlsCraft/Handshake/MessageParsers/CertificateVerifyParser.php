<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\Messages\CertificateVerify;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateVerifyParser extends AbstractMessageParser
{
    public function parse(string $data): CertificateVerify
    {
        $payload = $this->parseHandshake($data, HandshakeType::CERTIFICATE_VERIFY);

        $algorithm = unpack('n', substr($payload, 0, 2))[1];
        $sigLength = unpack('n', substr($payload, 2, 2))[1];
        $signature = substr($payload, 4, $sigLength);

        return new CertificateVerify(SignatureScheme::from($algorithm), $signature);
    }
}
