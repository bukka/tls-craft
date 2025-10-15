<?php

namespace Php\TlsCraft\Crypto;

interface KeyPair
{
    public function getPublicKey(): string;

    public function computeSharedSecret(mixed $peerPublicKey): string;
}
