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
            'Peer pub' => $peerPublicKey,
        ]);

        $peerPublicKeyResource = $this->keyExchange->getPeerPublicKey($peerPublicKey);

        Logger::debug('Peer key resource details', [
            'Input peer key' => bin2hex($peerPublicKey),
            'Resource type' => get_class($peerPublicKeyResource),
        ]);

        $sharedSecret = openssl_pkey_derive($peerPublicKeyResource, $this->privateKeyResource);

        if ($sharedSecret === false) {
            Logger::error('ECDH derive failed');
            throw new OpenSslException('Failed to compute shared secret');
        }

        Logger::debug('ECDH derive (ok)', [
            'Shared len' => strlen($sharedSecret),
            'Shared secret' => $sharedSecret,
        ]);

        return $sharedSecret;
    }
}
