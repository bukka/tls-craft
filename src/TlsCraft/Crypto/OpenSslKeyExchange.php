<?php

namespace Php\TlsCraft\Crypto;

interface OpenSslKeyExchange extends KeyExchange
{
    public function validatePeerPublicKey(string $peerPublicKey): void;
}
