<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\CertificateVerify;

class CertificateVerifySerializer extends AbstractMessageSerializer
{
    public function serialize(CertificateVerify $message): string
    {
        return pack('n', $message->algorithm->value).
            pack('n', strlen($message->signature)).
            $message->signature;
    }
}
