<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\KeyDerivation;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\HandshakeType;

class KeySchedule
{
    private string $hashAlgorithm;
    private int $hashLength;
    private ?string $earlySecret = null;
    private string $handshakeSecret;
    private string $masterSecret;
    private ?string $currentClientApplicationTrafficSecret = null;
    private ?string $currentServerApplicationTrafficSecret = null;

    public function __construct(
        private CipherSuite $cipherSuite,
        private KeyDerivation $keyDerivation,
        private HandshakeTranscript $transcript,
    ) {
        $this->hashAlgorithm = $cipherSuite->getHashAlgorithm();
        $this->hashLength = $cipherSuite->getHashLength();
    }

    public function deriveEarlySecret(?string $psk = null): void
    {
        $ikm = $psk ?? str_repeat("\x00", $this->hashLength);
        $this->earlySecret = $this->keyDerivation->hkdfExtract('', $ikm, $this->hashAlgorithm);

        Logger::debug('EARLY SECRET', [
            'IKM' => $ikm,
            'Early Secret' => $this->earlySecret,
        ]);
    }

    public function deriveHandshakeSecret(string $sharedSecret): void
    {
        if ($this->earlySecret === null) {
            $this->deriveEarlySecret();
        }

        $derivedSecret = $this->keyDerivation->deriveSecret(
            $this->earlySecret,
            'derived',
            '',
            $this->cipherSuite,
        );

        // handshake_secret = HKDF-Extract(derived_secret, ECDHE)
        $this->handshakeSecret = $this->keyDerivation->hkdfExtract(
            $derivedSecret,
            $sharedSecret,
            $this->hashAlgorithm,
        );

        Logger::debug('HANDSHAKE SECRET', [
            'Derived Secret' => $derivedSecret,
            'Handshake Secret' => $this->handshakeSecret,
        ]);
    }

    public function deriveMasterSecret(): void
    {
        $derivedSecret = $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            'derived',
            '',
            $this->cipherSuite,
        );

        // master_secret = HKDF-Extract(derived_secret2, 0^HashLen)
        $this->masterSecret = $this->keyDerivation->hkdfExtract(
            $derivedSecret,
            str_repeat("\x00", $this->hashLength),
            $this->hashAlgorithm,
        );

        Logger::debug('MASTER SECRET', [
            'Derived Secret' => $derivedSecret,
            'Handshake Secret' => $this->masterSecret,
        ]);
    }

    public function getClientHandshakeTrafficSecret(): string
    {
        $transcript = $this->transcript->getThrough(HandshakeType::SERVER_HELLO);

        $derivedSecret = $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            'c hs traffic',
            $transcript,
            $this->cipherSuite,
        );

        Logger::debug('HANDSHAKE CLIENT SECRET', [
            'Derived Secret' => $derivedSecret,
            'Transcript' => $transcript,
            'Types' => $this->transcript->getTypesThrough(HandshakeType::SERVER_HELLO),
        ]);

        return $derivedSecret;
    }

    public function getServerHandshakeTrafficSecret(): string
    {
        $transcript = $this->transcript->getThrough(HandshakeType::SERVER_HELLO);

        $derivedSecret = $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            's hs traffic',
            $this->transcript->getThrough(HandshakeType::SERVER_HELLO),
            $this->cipherSuite,
        );

        Logger::debug('HANDSHAKE SERVER SECRET', [
            'Derived Secret' => $derivedSecret,
            'Transcript' => $transcript,
            'Types' => $this->transcript->getTypesThrough(HandshakeType::SERVER_HELLO),
        ]);

        return $derivedSecret;
    }

    public function getClientApplicationTrafficSecret(): string
    {
        // Return stored secret if available (after key update), otherwise derive fresh
        if ($this->currentClientApplicationTrafficSecret !== null) {
            return $this->currentClientApplicationTrafficSecret;
        }

        $transcript = $this->transcript->getThrough(HandshakeType::FINISHED);

        $secret = $this->keyDerivation->deriveSecret(
            $this->masterSecret,
            'c ap traffic',
            $transcript,
            $this->cipherSuite,
        );

        Logger::debug('APPLICATION CLIENT SECRET', [
            'Derived Secret' => $secret,
            'Transcript' => $transcript,
            'Types' => $this->transcript->getTypesThrough(HandshakeType::FINISHED),
        ]);

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

        $transcript = $this->transcript->getThrough(HandshakeType::FINISHED);

        $secret = $this->keyDerivation->deriveSecret(
            $this->masterSecret,
            's ap traffic',
            $transcript,
            $this->cipherSuite,
        );

        Logger::debug('APPLICATION SERVER SECRET', [
            'Derived Secret' => $secret,
            'Transcript' => $transcript,
            'Types' => $this->transcript->getTypesThrough(HandshakeType::FINISHED),
        ]);

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
        // Hash the transcript up to and including the FINISHED message (should be only called by the client when creating FinishedMessage)
        $transcript = hash($this->hashAlgorithm, $this->transcript->getThrough(HandshakeType::FINISHED), true);

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

        Logger::debug('DERIVE APPLICATION KEYS', [
            'Traffic secret' => $trafficSecret,
            'Key' => $key,
            'IV' => $iv,
            'Cipher suite' => $this->cipherSuite->name,
        ]);

        return ['key' => $key, 'iv' => $iv];
    }

    public function updateTrafficSecret(string $trafficSecret): string
    {
        $trafficSecret = $this->keyDerivation->expandLabel(
            $trafficSecret,
            'traffic upd',
            '',
            $this->hashLength,
            $this->cipherSuite,
        );

        Logger::debug('DERIVE APPLICATION KEYS', [
            'Traffic secret' => $trafficSecret,
            'Hash length' => $this->hashLength,
            'Cipher suite' => $this->cipherSuite->name,
        ]);

        return $trafficSecret;
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
