<?php

namespace Php\TlsCraft\Crypto;

class KeySchedule
{
    private CipherSuite $cipherSuite;
    private string $hashAlgorithm;
    private int $hashLength;

    private string $earlySecret;
    private string $handshakeSecret;
    private string $masterSecret;
    private ?string $currentClientApplicationTrafficSecret = null;
    private ?string $currentServerApplicationTrafficSecret = null;
    private string $handshakeMessages = '';

    public function __construct(CipherSuite $cipherSuite)
    {
        $this->cipherSuite = $cipherSuite;
        $this->hashAlgorithm = $cipherSuite->getHashAlgorithm();
        $this->hashLength = $cipherSuite->getHashLength();

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
        $this->earlySecret = KeyDerivation::hkdfExtract('', $ikm, $this->hashAlgorithm);
    }

    public function deriveHandshakeSecret(string $sharedSecret): void
    {
        $derivedSecret = KeyDerivation::deriveSecret(
            $this->earlySecret,
            'derived',
            '',
            $this->cipherSuite,
        );

        $this->handshakeSecret = KeyDerivation::hkdfExtract(
            $derivedSecret,
            $sharedSecret,
            $this->hashAlgorithm,
        );
    }

    public function deriveMasterSecret(): void
    {
        $derivedSecret = KeyDerivation::deriveSecret(
            $this->handshakeSecret,
            'derived',
            '',
            $this->cipherSuite,
        );

        $this->masterSecret = KeyDerivation::hkdfExtract(
            $derivedSecret,
            str_repeat("\x00", $this->hashLength),
            $this->hashAlgorithm,
        );
    }

    public function getClientHandshakeTrafficSecret(): string
    {
        return KeyDerivation::deriveSecret(
            $this->handshakeSecret,
            'c hs traffic',
            $this->handshakeMessages,
            $this->cipherSuite,
        );
    }

    public function getServerHandshakeTrafficSecret(): string
    {
        return KeyDerivation::deriveSecret(
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

        $secret = KeyDerivation::deriveSecret(
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

        $secret = KeyDerivation::deriveSecret(
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
        return KeyDerivation::expandLabel(
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
        $key = KeyDerivation::expandLabel(
            $trafficSecret,
            'key',
            '',
            $this->cipherSuite->getKeyLength(),
            $this->cipherSuite,
        );

        $iv = KeyDerivation::expandLabel(
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
        return KeyDerivation::expandLabel(
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
