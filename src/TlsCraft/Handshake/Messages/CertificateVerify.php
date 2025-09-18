<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateVerify extends Message
{
    public function __construct(
        public readonly SignatureScheme $algorithm,
        public readonly string $signature,
    ) {
        parent::__construct(HandshakeType::CERTIFICATE_VERIFY);
    }

    public function encode(): string
    {
        return pack('n', $this->algorithm->value).
            pack('n', strlen($this->signature)).
            $this->signature;
    }

    public static function decode(string $data): static
    {
        $algorithm = unpack('n', substr($data, 0, 2))[1];
        $sigLength = unpack('n', substr($data, 2, 2))[1];
        $signature = substr($data, 4, $sigLength);

        return new self(SignatureScheme::from($algorithm), $signature);
    }
}
