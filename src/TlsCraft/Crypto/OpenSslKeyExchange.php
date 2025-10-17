<?php

namespace Php\TlsCraft\Crypto;

interface OpenSslKeyExchange extends KeyExchange
{
    public function getPeerPublicKey(string $peerPublicKey): mixed;
}
