<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

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
        $this->keyExchange->validatePeerPublicKey($peerPublicKey);
        $sharedSecret = openssl_dh_compute_key($peerPublicKey, $this->privateKeyResource);

        if ($sharedSecret === false) {
            throw new CryptoException('Failed to compute shared secret: '.openssl_error_string());
        }

        return $sharedSecret;
    }
}
