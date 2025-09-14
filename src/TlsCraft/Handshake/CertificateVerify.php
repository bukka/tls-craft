<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Protocol\HandshakeType;

class CertificateVerify extends HandshakeMessage
{
    public function __construct(
        public readonly int    $algorithm,
        public readonly string $signature
    )
    {
        parent::__construct(HandshakeType::CERTIFICATE_VERIFY);
    }

    public function encode(): string
    {
        return pack('n', $this->algorithm) .
            pack('n', strlen($this->signature)) .
            $this->signature;
    }

    public static function decode(string $data): static
    {
        $algorithm = unpack('n', substr($data, 0, 2))[1];
        $sigLength = unpack('n', substr($data, 2, 2))[1];
        $signature = substr($data, 4, $sigLength);

        return new self($algorithm, $signature);
    }
}
