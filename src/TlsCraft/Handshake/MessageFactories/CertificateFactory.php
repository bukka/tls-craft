<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Handshake\Messages\Certificate;

class CertificateFactory extends AbstractMessageFactory
{
    public function create(CertificateChain $certificateChain): Certificate
    {
        return new Certificate('', $certificateChain);
    }
}
