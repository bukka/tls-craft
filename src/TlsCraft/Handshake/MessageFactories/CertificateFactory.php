<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\Certificate;

class CertificateFactory extends AbstractMessageFactory
{
    public function create(array $certificateChain): Certificate
    {
        return new Certificate('', $certificateChain);
    }
}