<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\KeyDerivation;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\HandshakeType;
use RuntimeException;

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

    // =========================================================================
    // EARLY SECRET DERIVATION (PSK/Resumption)
    // =========================================================================

    /**
     * Derive early secret without PSK (standard handshake)
     *
     * Early Secret = HKDF-Extract(salt=0, IKM=0)
     */
    public function deriveEarlySecret(?string $psk = null): void
    {
        $ikm = $psk ?? str_repeat("\x00", $this->hashLength);
        $this->earlySecret = $this->keyDerivation->hkdfExtract('', $ikm, $this->hashAlgorithm);

        Logger::debug('EARLY SECRET', [
            'IKM' => $ikm,
            'Early Secret' => $this->earlySecret,
        ]);
    }

    /**
     * Derive early secret with PSK (resumption handshake)
     *
     * Early Secret = HKDF-Extract(salt=0, IKM=PSK or 0)
     *
     * @param string|null $psk Pre-shared key or null for zero IKM
     */
    public function deriveEarlySecretWithPsk(?string $psk): void
    {
        $ikm = $psk ?? str_repeat("\x00", $this->hashLength);
        $this->earlySecret = $this->keyDerivation->hkdfExtract('', $ikm, $this->hashAlgorithm);

        Logger::debug('EARLY SECRET (with PSK)', [
            'has_psk' => $psk !== null,
            'IKM' => $ikm,
            'Early Secret' => $this->earlySecret,
        ]);
    }

    /**
     * Get early secret (for PSK binder derivation)
     */
    public function getEarlySecret(): ?string
    {
        return $this->earlySecret;
    }

    /**
     * Check if early secret has been derived
     */
    public function hasEarlySecret(): bool
    {
        return $this->earlySecret !== null;
    }

    /**
     * Derive client early traffic secret (for 0-RTT data)
     *
     * client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
     *
     * @param string $clientHelloData The serialized ClientHello message
     */
    public function getClientEarlyTrafficSecret(string $clientHelloData): string
    {
        if ($this->earlySecret === null) {
            throw new RuntimeException('Cannot derive early traffic secret: early secret not set');
        }

        $secret = $this->keyDerivation->deriveSecret(
            $this->earlySecret,
            'c e traffic',
            $clientHelloData,
            $this->cipherSuite,
        );

        Logger::debug('CLIENT EARLY TRAFFIC SECRET', [
            'Early Secret' => $this->earlySecret,
            'ClientHello length' => strlen($clientHelloData),
            'Client Early Traffic Secret' => $secret,
        ]);

        return $secret;
    }

    /**
     * Derive early exporter master secret (optional, for early exporters)
     *
     * early_exporter_master_secret = Derive-Secret(early_secret, "e exp master", ClientHello)
     */
    public function getEarlyExporterMasterSecret(string $clientHelloData): string
    {
        if ($this->earlySecret === null) {
            throw new RuntimeException('Cannot derive early exporter secret: early secret not set');
        }

        return $this->keyDerivation->deriveSecret(
            $this->earlySecret,
            'e exp master',
            $clientHelloData,
            $this->cipherSuite,
        );
    }

    // =========================================================================
    // PSK BINDER DERIVATION
    // =========================================================================

    /**
     * Derive PSK binder key from early secret
     *
     * binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
     *
     * @param bool $isExternal True for external PSK, false for resumption PSK
     */
    public function derivePskBinderKey(bool $isExternal = false): string
    {
        if ($this->earlySecret === null) {
            throw new RuntimeException('Cannot derive binder key: early secret not set');
        }

        $label = $isExternal ? 'ext binder' : 'res binder';
        $binderKey = $this->keyDerivation->deriveSecret(
            $this->earlySecret,
            $label,
            '',
            $this->cipherSuite,
        );

        Logger::debug('PSK BINDER KEY', [
            'is_external' => $isExternal,
            'label' => $label,
            'Binder Key' => $binderKey,
        ]);

        return $binderKey;
    }

    /**
     * Derive finished key for PSK binder
     *
     * finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
     */
    public function deriveFinishedKeyForBinder(string $binderKey): string
    {
        $finishedKey = $this->keyDerivation->expandLabel(
            $binderKey,
            'finished',
            '',
            $this->hashLength,
            $this->cipherSuite,
        );

        Logger::debug('PSK BINDER FINISHED KEY', [
            'Finished Key' => $finishedKey,
        ]);

        return $finishedKey;
    }

    /**
     * Calculate PSK binder value
     *
     * binder = HMAC(finished_key, Transcript-Hash(partial_transcript))
     *
     * @param string $finishedKey    The finished key derived from binder key
     * @param string $transcriptData Raw transcript data (ClientHello without binders)
     */
    public function calculatePskBinder(string $finishedKey, string $transcriptData): string
    {
        $transcriptHash = hash($this->hashAlgorithm, $transcriptData, true);
        $binder = hash_hmac($this->hashAlgorithm, $transcriptHash, $finishedKey, true);

        Logger::debug('PSK BINDER', [
            'Transcript length' => strlen($transcriptData),
            'Transcript Hash' => $transcriptHash,
            'Binder' => $binder,
        ]);

        return $binder;
    }

    // =========================================================================
    // HANDSHAKE SECRET DERIVATION
    // =========================================================================

    /**
     * Derive handshake secret from ECDHE shared secret
     *
     * handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", ""), ECDHE)
     */
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

    /**
     * Get client handshake traffic secret
     *
     * client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", ClientHello...ServerHello)
     */
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

    /**
     * Get server handshake traffic secret
     *
     * server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", ClientHello...ServerHello)
     */
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

    /**
     * Check if handshake keys have been derived
     */
    public function hasHandshakeKeys(): bool
    {
        return isset($this->handshakeSecret);
    }

    // =========================================================================
    // MASTER SECRET DERIVATION
    // =========================================================================

    /**
     * Derive master secret
     *
     * master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
     */
    public function deriveMasterSecret(): void
    {
        $derivedSecret = $this->keyDerivation->deriveSecret(
            $this->handshakeSecret,
            'derived',
            '',
            $this->cipherSuite,
        );

        // master_secret = HKDF-Extract(derived_secret, 0^HashLen)
        $this->masterSecret = $this->keyDerivation->hkdfExtract(
            $derivedSecret,
            str_repeat("\x00", $this->hashLength),
            $this->hashAlgorithm,
        );

        Logger::debug('MASTER SECRET', [
            'Derived Secret' => $derivedSecret,
            'Master Secret' => $this->masterSecret,
        ]);
    }

    /**
     * Check if master secret has been derived
     */
    public function hasMasterSecret(): bool
    {
        return isset($this->masterSecret);
    }

    // =========================================================================
    // APPLICATION TRAFFIC SECRETS
    // =========================================================================

    /**
     * Get client application traffic secret
     *
     * client_application_traffic_secret = Derive-Secret(master_secret, "c ap traffic", ClientHello...server Finished)
     */
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

    /**
     * Get server application traffic secret
     *
     * server_application_traffic_secret = Derive-Secret(master_secret, "s ap traffic", ClientHello...server Finished)
     */
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

    /**
     * Set client application traffic secret (after key update)
     */
    public function setClientApplicationTrafficSecret(string $secret): void
    {
        $this->currentClientApplicationTrafficSecret = $secret;
    }

    /**
     * Set server application traffic secret (after key update)
     */
    public function setServerApplicationTrafficSecret(string $secret): void
    {
        $this->currentServerApplicationTrafficSecret = $secret;
    }

    /**
     * Check if application secrets have been derived
     */
    public function hasApplicationSecrets(): bool
    {
        return isset($this->masterSecret);
    }

    /**
     * Update traffic secret (for KeyUpdate)
     *
     * application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
     */
    public function updateTrafficSecret(string $trafficSecret): string
    {
        $trafficSecret = $this->keyDerivation->expandLabel(
            $trafficSecret,
            'traffic upd',
            '',
            $this->hashLength,
            $this->cipherSuite,
        );

        Logger::debug('UPDATE TRAFFIC SECRET', [
            'Updated Traffic Secret' => $trafficSecret,
            'Hash length' => $this->hashLength,
            'Cipher suite' => $this->cipherSuite->name,
        ]);

        return $trafficSecret;
    }

    // =========================================================================
    // TRAFFIC KEY DERIVATION
    // =========================================================================

    /**
     * Derive traffic keys (key and IV) from traffic secret
     *
     * key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
     * iv = HKDF-Expand-Label(traffic_secret, "iv", "", iv_length)
     */
    public function deriveTrafficKeys(string $trafficSecret): array
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

        Logger::debug('DERIVE TRAFFIC KEYS', [
            'Traffic secret' => $trafficSecret,
            'Key' => $key,
            'IV' => $iv,
            'Cipher suite' => $this->cipherSuite->name,
        ]);

        return ['key' => $key, 'iv' => $iv];
    }

    // =========================================================================
    // FINISHED MESSAGE
    // =========================================================================

    /**
     * Get finished key from traffic secret
     *
     * finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
     */
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

    /**
     * Calculate finished data (verify_data)
     *
     * verify_data = HMAC(finished_key, Transcript-Hash(messages))
     *
     * @param string $finishedKey The finished key
     * @param bool   $forClient   True if calculating for client Finished, false for server
     */
    public function calculateFinishedData(string $finishedKey, bool $forClient): string
    {
        // Hash the transcript up to (but not including) the Finished message being created
        $transcriptData = $forClient
            ? $this->transcript->getAll()  // Client: all messages before client Finished
            : $this->transcript->getThrough(HandshakeType::FINISHED);  // Server: up to server Finished

        $transcript = hash($this->hashAlgorithm, $transcriptData, true);

        return hash_hmac($this->hashAlgorithm, $transcript, $finishedKey, true);
    }

    // =========================================================================
    // RESUMPTION (SESSION TICKETS)
    // =========================================================================

    /**
     * Derive resumption master secret (used for creating session tickets)
     *
     * RFC 8446 § 4.6.1:
     * resumption_master_secret = Derive-Secret(master_secret, "res master", ClientHello...client Finished)
     */
    public function deriveResumptionMasterSecret(): string
    {
        if (!isset($this->masterSecret)) {
            throw new RuntimeException('Cannot derive resumption master secret: master secret not set');
        }

        // The transcript includes ALL handshake messages up to and including client Finished
        $transcript = $this->transcript->getAllExceptLast();

        $resumptionMasterSecret = $this->keyDerivation->deriveSecret(
            $this->masterSecret,
            'res master',
            $transcript,
            $this->cipherSuite,
        );

        Logger::debug('RESUMPTION MASTER SECRET', [
            'Resumption Master Secret' => $resumptionMasterSecret,
            'Transcript length' => strlen($transcript),
            'Message count' => $this->transcript->count(),
            'Types' => $this->transcript->getAllTypes(),
        ]);

        return $resumptionMasterSecret;
    }

    /**
     * Derive resumption secret from resumption master secret and ticket nonce
     *
     * PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
     *
     * This is the actual PSK that will be used in a resumed handshake
     */
    public function deriveResumptionSecret(string $resumptionMasterSecret, string $ticketNonce): string
    {
        $resumptionSecret = $this->keyDerivation->expandLabel(
            $resumptionMasterSecret,
            'resumption',
            $ticketNonce,
            $this->hashLength,
            $this->cipherSuite,
        );

        Logger::debug('RESUMPTION SECRET (PSK)', [
            'Ticket Nonce' => $ticketNonce,
            'Resumption Secret' => $resumptionSecret,
        ]);

        return $resumptionSecret;
    }
}
