<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateVerifyMessage extends Message
{
    public function __construct(
        public readonly SignatureScheme $algorithm,
        public readonly string $signature,
    ) {
        parent::__construct(HandshakeType::CERTIFICATE_VERIFY);
    }
}
