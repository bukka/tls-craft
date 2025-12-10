<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;

class CertificateFactory extends AbstractMessageFactory
{
    public function create(CertificateChain $certificateChain): CertificateMessage
    {
        return new CertificateMessage('', $certificateChain);
    }
}
