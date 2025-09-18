<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\Certificate;

class CertificateFactory extends AbstractMessageFactory
{
    public function create(array $certificateChain): Certificate
    {
        return new Certificate('', $certificateChain);
    }
}