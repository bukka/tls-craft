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
}
