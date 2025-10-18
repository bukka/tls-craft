<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\OpenSslException;

class OpenSslKeyPair implements KeyPair
{
    public function __construct(
        private $privateKeyResource,
        private string $publicKey,
        private OpenSslKeyExchange $keyExchange,
    ) {
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function computeSharedSecret(string $peerPublicKey): string
    {
        $peerPublicKeyResource = $this->keyExchange->getPeerPublicKey($peerPublicKey);
        $sharedSecret = openssl_pkey_derive($peerPublicKeyResource, $this->privateKeyResource);

        if ($sharedSecret === false) {
            throw new OpenSslException('Failed to compute shared secret');
        }

        return $sharedSecret;
    }
}
