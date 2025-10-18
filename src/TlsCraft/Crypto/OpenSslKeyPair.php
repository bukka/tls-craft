<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\OpenSslException;
use Php\TlsCraft\Logger;

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
        Logger::debug('ECDH derive (pre)', [
            'Peer pub len' => strlen($peerPublicKey),
            'Peer pub (pref)' => substr($peerPublicKey, 0, 16),
        ]);

        $peerPublicKeyResource = $this->keyExchange->getPeerPublicKey($peerPublicKey);
        $sharedSecret = openssl_pkey_derive($peerPublicKeyResource, $this->privateKeyResource);

        if ($sharedSecret === false) {
            Logger::error('ECDH derive failed');
            throw new OpenSslException('Failed to compute shared secret');
        }

        Logger::debug('ECDH derive (ok)', [
            'Shared len' => strlen($sharedSecret),
            'Shared (pref)' => substr($sharedSecret, 0, 16),
        ]);

        return $sharedSecret;
    }
}
