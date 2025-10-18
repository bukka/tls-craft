<?php

namespace Php\TlsCraft\Crypto;

class KeySchedule
{
    private CipherSuite $cipherSuite;

    private KeyDerivation $keyDerivation;
    private string $hashAlgorithm;
    private int $hashLength;

    private string $earlySecret;
    private string $handshakeSecret;
    private string $masterSecret;
    private ?string $currentClientApplicationTrafficSecret = null;
    private ?string $currentServerApplicationTrafficSecret = null;
    private string $handshakeMessages = '';

    public function __construct(CipherSuite $cipherSuite, KeyDerivation $keyDerivation)
    {
        $this->cipherSuite = $cipherSuite;
        $this->hashAlgorithm = $cipherSuite->getHashAlgorithm();
        $this->hashLength = $cipherSuite->getHashLength();
        $this->keyDerivation = $keyDerivation;

        // Initialize with zeros
        $this->earlySecret = str_repeat("\x00", $this->hashLength);
    }

    public function addHandshakeMessage(string $message): void
    {
        $this->handshakeMessages .= $message;
    }

    public function deriveEarlySecret(?string $psk = null): void
    {
        $ikm = $psk ?? str_repeat("\x00", $this->hashLength);
        $this->earlySecret = $this->keyDerivation->hkdfExtract('', $ikm, $this->hashAlgorithm);
    }

    public function deriveHandshakeSecret(string $sharedSecret): void
    {
        // derived_secret = Expand-Label(early_secret, "derived", "", HashLen)
        $derivedSecret = $this->keyDerivation->expandLabel(
            $this->earlySecret,
            'derived',
            '',
            $this->hashLength,
            $this->cipherSuite
        );

        // handshake_secret = HKDF-Extract(derived_secret, ECDHE)
        $this->handshakeSecret = $this->keyDerivation->hkdfExtract(
            $derivedSecret,
            $sharedSecret,
            $this->hashAlgorithm
        );
    }

    public function deriveMasterSecret(): void
    {
        // derived_secret2 = Expand-Label(handshake_secret, "derived", "", HashLen)
        $derivedSecret = $this->keyDerivation->expandLabel(
            $this->handshakeSecret,
            'derived',
            '',
            $this->hashLength,
            $this->cipherSuite
        );

        // master_secret = HKDF-Extract(derived_secret2, 0^HashLen)
        $this->masterSecret = $this->keyDerivation->hkdfExtract(
            $derivedSecret,
            str_repeat("\x00", $this->hashLength),
            $this->hashAlgorithm
        );
    }

    public function getClientHandshakeTrafficSecret(): string
    {
        return $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            'c hs traffic',
            $this->handshakeMessages,
            $this->cipherSuite,
        );
    }

    public function getServerHandshakeTrafficSecret(): string
    {
        return $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            's hs traffic',
            $this->handshakeMessages,
            $this->cipherSuite,
        );
    }

    public function getClientApplicationTrafficSecret(): string
    {
        // Return stored secret if available (after key update), otherwise derive fresh
        if ($this->currentClientApplicationTrafficSecret !== null) {
            return $this->currentClientApplicationTrafficSecret;
        }

        $secret = $this->keyDerivation->deriveSecret(
            $this->masterSecret,
            'c ap traffic',
            $this->handshakeMessages,
            $this->cipherSuite,
        );

        // Store for future updates
        $this->currentClientApplicationTrafficSecret = $secret;

        return $secret;
    }

    public function getServerApplicationTrafficSecret(): string
    {
        // Return stored secret if available (after key update), otherwise derive fresh
        if ($this->currentServerApplicationTrafficSecret !== null) {
            return $this->currentServerApplicationTrafficSecret;
        }

        $secret = $this->keyDerivation->deriveSecret(
            $this->masterSecret,
            's ap traffic',
            $this->handshakeMessages,
            $this->cipherSuite,
        );

        // Store for future updates
        $this->currentServerApplicationTrafficSecret = $secret;

        return $secret;
    }

    public function setClientApplicationTrafficSecret(string $secret): void
    {
        $this->currentClientApplicationTrafficSecret = $secret;
    }

    public function setServerApplicationTrafficSecret(string $secret): void
    {
        $this->currentServerApplicationTrafficSecret = $secret;
    }

    public function getFinishedKey(string $trafficSecret): string
    {
        return $this->keyDerivation->expandLabel(
            $trafficSecret,
            'finished',
            '',
            $this->hashLength,
            $this->cipherSuite,
        );
    }

    public function calculateFinishedData(string $finishedKey): string
    {
        $transcript = hash($this->hashAlgorithm, $this->handshakeMessages, true);

        return hash_hmac($this->hashAlgorithm, $transcript, $finishedKey, true);
    }

    public function deriveApplicationKeys(string $trafficSecret): array
    {
        $key = $this->keyDerivation->expandLabel(
            $trafficSecret,
            'key',
            '',
            $this->cipherSuite->getKeyLength(),
            $this->cipherSuite,
        );

        $iv = $this->keyDerivation->expandLabel(
            $trafficSecret,
            'iv',
            '',
            $this->cipherSuite->getIVLength(),
            $this->cipherSuite,
        );

        return ['key' => $key, 'iv' => $iv];
    }

    public function updateTrafficSecret(string $trafficSecret): string
    {
        return $this->keyDerivation->expandLabel(
            $trafficSecret,
            'traffic upd',
            '',
            $this->hashLength,
            $this->cipherSuite,
        );
    }

    public function hasApplicationSecrets(): bool
    {
        return isset($this->masterSecret);
    }

    public function hasHandshakeKeys(): bool
    {
        return isset($this->handshakeSecret);
    }
}
