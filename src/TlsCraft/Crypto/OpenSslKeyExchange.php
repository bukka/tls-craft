<?php

namespace Php\TlsCraft\Crypto;

interface OpenSslKeyExchange extends KeyExchange
{
    public function getPeerKeyResource(string $peerPublicKey): mixed;
}
