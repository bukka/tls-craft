<?php

namespace Php\TlsCraft;

use OpenSSLAsymmetricKey;
use Php\TlsCraft\Crypto\{CertificateChain,
    CipherSuite,
    CryptoFactory,
    KeyPair,
    KeyShare,
    NamedGroup,
    PrivateKey,
    RandomGenerator,
    SignatureScheme};
use Php\TlsCraft\Exceptions\{CraftException, CryptoException, ProtocolViolationException};
use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;
use Php\TlsCraft\Handshake\HandshakeTranscript;
use Php\TlsCraft\Handshake\KeySchedule;
use Php\TlsCraft\Handshake\PskBinderCalculator;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Session\PreSharedKey;
use Php\TlsCraft\Session\SessionTicket;

/**
 * Updated Context with missing methods
 */
class Context
{
    private RandomGenerator $randomGenerator;
    private Version $negotiatedVersion;
    private ?CipherSuite $negotiatedCipherSuite = null;
    private ?SignatureScheme $negotiatedSignatureScheme = null;

    // Crypto state
    private ?KeySchedule $keySchedule = null;
    private ?string $sharedSecret = null;

    // Random values
    private ?string $clientRandom = null;
    private ?string $serverRandom = null;

    // Certificate chain and private key
    private ?CertificateChain $serverCertificateChain = null;
    private ?PrivateKey $serverPrivateKey = null;
    private ?CertificateChain $clientCertificateChain = null;
    private ?PrivateKey $clientPrivateKey = null;
    private array $clientSignatureAlgorithms = [];
    private array $serverSignatureAlgorithms = [];

    // Handshake
    private ?string $clientHelloSessionId = null;
    private ?KeyShare $keyShare;
    private ?string $requestedServerName = null;
    private array $clientOfferedProtocols;
    private ?string $selectedProtocol = null;
    private ?KeyShare $serverKeyShare = null;
    private bool $serverNameAcknowledged;
    private array $serverSupportedGroups;
    private OpenSSLAsymmetricKey $peerPublicKey;
    private ?string $certificateRequestContext = null;
    private bool $certificateVerified;
    private bool $handshakeComplete = false;

    // PSK/Session Resumption state
    /** @var PreSharedKey[] */
    private array $offeredPsks = [];
    private ?PreSharedKey $selectedPsk = null;
    private ?int $selectedPskIndex = null;
    private bool $isResuming = false;
    private ?string $resumptionSecret = null;
    private ?PskBinderCalculator $pskBinderCalculator = null;
    /** @var int[] */
    private array $pskKeyExchangeModes = [];
    /** @var SessionTicket[] */
    private array $sessionTickets = [];

    private array $currentDecryptionKeys = [];
    private array $currentEncryptionKeys = [];
    private int $readSequenceNumber = 0;
    private int $writeSequenceNumber = 0;

    /** @var KeyPair[] */
    private array $keyPairs = [];

    public function __construct(
        private bool $isClient,
        private Config $config,
        private CryptoFactory $cryptoFactory,
        private HandshakeTranscript $handshakeTranscript,
    ) {
        $this->randomGenerator = $this->cryptoFactory->createRandomGenerator();
    }

    // === Getters ===

    public function getConfig(): Config
    {
        return $this->config;
    }

    public function getCryptoFactory(): CryptoFactory
    {
        return $this->cryptoFactory;
    }

    public function isClient(): bool
    {
        return $this->isClient;
    }

    public function setNegotiatedVersion(Version $version): void
    {
        $this->negotiatedVersion = $version;
    }

    public function getNegotiatedVersion(): Version
    {
        return $this->negotiatedVersion;
    }

    public function getNegotiatedCipherSuite(): ?CipherSuite
    {
        return $this->negotiatedCipherSuite;
    }

    public function getNegotiatedSignatureScheme(): ?SignatureScheme
    {
        return $this->negotiatedSignatureScheme;
    }

    public function getKeySchedule(): ?KeySchedule
    {
        return $this->keySchedule;
    }

    public function getClientRandom(): ?string
    {
        if ($this->clientRandom === null) {
            $this->clientRandom = $this->randomGenerator->generateClientRandom();
        }

        return $this->clientRandom;
    }

    public function getServerRandom(): ?string
    {
        if ($this->serverRandom === null) {
            $this->serverRandom = $this->randomGenerator->generateServerRandom();
        }

        return $this->serverRandom;
    }

    public function getClientHelloSessionId(): string
    {
        return $this->clientHelloSessionId ?? '';
    }

    public function getSharedSecret(): ?string
    {
        return $this->sharedSecret;
    }

    // === Setters ===

    public function setNegotiatedCipherSuite(CipherSuite $cipherSuite): void
    {
        $this->negotiatedCipherSuite = $cipherSuite;
        $this->keySchedule = $this->cryptoFactory->createKeySchedule($cipherSuite, $this->handshakeTranscript);
    }

    public function setNegotiatedSignatureScheme(SignatureScheme $scheme): void
    {
        $this->negotiatedSignatureScheme = $scheme;
    }

    public function setClientRandom(string $random): void
    {
        if (strlen($random) !== 32) {
            throw new ProtocolViolationException('Client random must be 32 bytes');
        }
        $this->clientRandom = $random;
    }

    public function setClientHelloSessionId(string $sessionId): void
    {
        $this->clientHelloSessionId = $sessionId;
    }

    public function setServerRandom(string $random): void
    {
        if (strlen($random) !== 32) {
            throw new ProtocolViolationException('Server random must be 32 bytes');
        }
        $this->serverRandom = $random;
    }

    // === Handshake Transcript ===

    public function addHandshakeMessage(string $wireFormat): void
    {
        $this->handshakeTranscript->addMessage($wireFormat);
    }

    public function getHandshakeTranscript(): HandshakeTranscript
    {
        return $this->handshakeTranscript;
    }

    // === Key Derivation ===

    public function deriveEarlySecret(?string $psk = null): void
    {
        if (!$this->keySchedule) {
            throw new CraftException('Cannot derive early secret: missing key schedule');
        }
        $this->keySchedule->deriveEarlySecret($psk);
    }

    public function deriveHandshakeSecrets(): void
    {
        if (!$this->keySchedule || !$this->sharedSecret) {
            $missing = [];
            if (!$this->keySchedule) {
                $missing[] = 'key schedule';
            }
            if (!$this->sharedSecret) {
                $missing[] = 'shared secret';
            }
            throw new CraftException('Cannot derive handshake secrets: missing '.implode(' and ', $missing));
        }

        $this->keySchedule->deriveHandshakeSecret($this->sharedSecret);
    }

    public function deriveApplicationSecrets(): void
    {
        if (!$this->keySchedule) {
            throw new CraftException('Cannot derive application secrets: missing key schedule');
        }

        $this->keySchedule->deriveMasterSecret();
    }

    public function getHandshakeKeys(bool $forClient): array
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientHandshakeTrafficSecret() :
            $this->keySchedule->getServerHandshakeTrafficSecret();

        return $this->keySchedule->deriveTrafficKeys($trafficSecret);
    }

    public function getApplicationKeys(bool $forClient): array
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientApplicationTrafficSecret() :
            $this->keySchedule->getServerApplicationTrafficSecret();

        return $this->keySchedule->deriveTrafficKeys($trafficSecret);
    }

    public function getFinishedData(bool $forClient): string
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientHandshakeTrafficSecret() :
            $this->keySchedule->getServerHandshakeTrafficSecret();

        $finishedKey = $this->keySchedule->getFinishedKey($trafficSecret);

        return $this->keySchedule->calculateFinishedData($finishedKey, $forClient);
    }

    // === Traffic Key Updates ===

    public function updateTrafficKeys(): void
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        // Update both client and server traffic secrets
        $clientSecret = $this->keySchedule->getClientApplicationTrafficSecret();
        $serverSecret = $this->keySchedule->getServerApplicationTrafficSecret();

        $newClientSecret = $this->keySchedule->updateTrafficSecret($clientSecret);
        $newServerSecret = $this->keySchedule->updateTrafficSecret($serverSecret);

        // Derive new keys from updated secrets
        $clientKeys = $this->keySchedule->deriveTrafficKeys($newClientSecret);
        $serverKeys = $this->keySchedule->deriveTrafficKeys($newServerSecret);

        // Store updated secrets (in a real implementation, these would update the key schedule)
        // For now, this is a placeholder for the key update process
    }

    public function setClientKeyShare(KeyShare $keyShare)
    {
        $this->keyShare = $keyShare;
    }

    public function getClientKeyShare(): KeyShare
    {
        return $this->keyShare;
    }

    public function setRequestedServerName(string $serverName)
    {
        $this->requestedServerName = $serverName;
    }

    public function getRequestedServerName(): ?string
    {
        return $this->requestedServerName;
    }

    public function setClientOfferedProtocols(array $protocols)
    {
        $this->clientOfferedProtocols = $protocols;
    }

    public function getClientOfferedProtocols(): array
    {
        return $this->clientOfferedProtocols;
    }

    public function setSelectedProtocol(string $alpnProtocol)
    {
        $this->selectedProtocol = $alpnProtocol;
    }

    public function getSelectedProtocol(): ?string
    {
        return $this->selectedProtocol;
    }

    public function setServerKeyShare(KeyShare $serverKeyShare)
    {
        $this->serverKeyShare = $serverKeyShare;
    }

    public function getServerKeyShare(): KeyShare
    {
        return $this->serverKeyShare;
    }

    public function setSharedSecret(string $sharedSecret)
    {
        $this->sharedSecret = $sharedSecret;
    }

    public function setServerNameAcknowledged(bool $value)
    {
        $this->serverNameAcknowledged = $value;
    }

    public function isServerNameAcknowledged(): bool
    {
        return $this->serverNameAcknowledged;
    }

    public function setServerSupportedGroups(array $serverSupportedGroups)
    {
        $this->serverSupportedGroups = $serverSupportedGroups;
    }

    public function getServerSupportedGroups(): array
    {
        return $this->serverSupportedGroups;
    }

    public function setPeerPublicKey(OpenSSLAsymmetricKey $publicKey)
    {
        $this->peerPublicKey = $publicKey;
    }

    public function getPeerPublicKey(): OpenSSLAsymmetricKey
    {
        return $this->peerPublicKey;
    }

    public function setCertificateRequestContext(string $context)
    {
        $this->certificateRequestContext = $context;
    }

    public function getCertificateRequestContext(): ?string
    {
        return $this->certificateRequestContext;
    }

    public function setCertificateVerified(bool $value)
    {
        $this->certificateVerified = $value;
    }

    public function isCertificateVerified(): bool
    {
        return $this->certificateVerified;
    }

    public function canDeriveApplicationSecrets(): bool
    {
        return $this->keySchedule && $this->keySchedule->hasMasterSecret();
    }

    public function isHandshakeComplete(): bool
    {
        return $this->handshakeComplete;
    }

    // === Certificate and keys ===

    public function setCertificateChainFromFile(string $path): void
    {
        if ($this->isClient()) {
            $this->setClientCertificateChainFromFile($path);
        } else {
            $this->setServerCertificateChainFromFile($path);
        }
    }

    public function setPrivateKeyFromFile(string $path, ?string $passphrase = null): void
    {
        if ($this->isClient()) {
            $this->setClientPrivateKeyFromFile($path, $passphrase);
        } else {
            $this->setServerPrivateKeyFromFile($path, $passphrase);
        }
    }

    public function setServerCertificateChain(CertificateChain $certificateChain): void
    {
        $this->serverCertificateChain = $certificateChain;
    }

    public function setServerCertificateChainFromFile(string $path): void
    {
        $this->serverCertificateChain = $this->cryptoFactory->createCertificateChainFromFile($path);
    }

    public function setServerPrivateKeyFromFile(string $path, ?string $passphrase = null): void
    {
        $this->serverPrivateKey = $this->cryptoFactory->createPrivateKeyFromFile($path, $passphrase);

        // Validate that key matches certificate if both are set
        if ($this->serverCertificateChain
            && !$this->serverPrivateKey->matchesCertificate($this->serverCertificateChain->getLeafCertificate())) {
            throw new CryptoException('Private key does not match leaf certificate');
        }
    }

    public function setClientCertificateChain(CertificateChain $certificateChain): void
    {
        $this->clientCertificateChain = $certificateChain;
    }

    public function setClientCertificateChainFromFile(string $path): void
    {
        $this->clientCertificateChain = $this->cryptoFactory->createCertificateChainFromFile($path);
    }

    public function setClientPrivateKeyFromFile(string $path, ?string $passphrase = null): void
    {
        $this->clientPrivateKey = $this->cryptoFactory->createPrivateKeyFromFile($path, $passphrase);

        // Validate that key matches certificate if both are set
        if ($this->clientCertificateChain
            && !$this->clientPrivateKey->matchesCertificate($this->clientCertificateChain->getLeafCertificate())) {
            throw new CryptoException('Private key does not match leaf certificate');
        }
    }

    public function loadCertificateFromConfig(): void
    {
        $config = $this->getConfig();

        if (!$config->hasCertificate()) {
            Logger::debug('No certificate configured in Config');

            return; // No certificate configured
        }

        $certFile = $config->getCertificateFile();
        $keyFile = $config->getPrivateKeyFile();
        $passphrase = $config->getPrivateKeyPassphrase();

        Logger::debug('Loading certificate from config', [
            'Cert file' => $certFile,
            'Key file' => $keyFile,
            'Has passphrase' => $passphrase !== null,
        ]);

        // Load certificate chain
        $this->setCertificateChainFromFile($certFile);

        // Load private key
        $this->setPrivateKeyFromFile($keyFile, $passphrase);
    }

    public function getServerCertificateChain(): CertificateChain
    {
        if (!$this->serverCertificateChain) {
            throw new CraftException('Certificate chain not set');
        }

        return $this->serverCertificateChain;
    }

    public function getServerPrivateKey(): ?PrivateKey
    {
        return $this->serverPrivateKey;
    }

    public function getClientCertificateChain(): CertificateChain
    {
        if (!$this->clientCertificateChain) {
            throw new CraftException('Certificate chain not set');
        }

        return $this->clientCertificateChain;
    }

    public function getClientPrivateKey(): ?PrivateKey
    {
        return $this->clientPrivateKey;
    }

    public function setClientSignatureAlgorithms(array $algorithms): void
    {
        $this->clientSignatureAlgorithms = $algorithms;
    }

    public function getClientSignatureAlgorithms(): array
    {
        return $this->clientSignatureAlgorithms;
    }

    public function setServerSignatureAlgorithms(array $algorithms): void
    {
        $this->serverSignatureAlgorithms = $algorithms;
    }

    public function getServerSignatureAlgorithms(): array
    {
        return $this->serverSignatureAlgorithms;
    }

    // === Application Traffic Secret Management ===

    public function getServerApplicationTrafficSecret(): string
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        return $this->keySchedule->getServerApplicationTrafficSecret();
    }

    public function getClientApplicationTrafficSecret(): string
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }

        return $this->keySchedule->getClientApplicationTrafficSecret();
    }

    public function setServerApplicationTrafficSecret(string $secret): void
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }
        $this->keySchedule->setServerApplicationTrafficSecret($secret);
    }

    public function setClientApplicationTrafficSecret(string $secret): void
    {
        if (!$this->keySchedule) {
            throw new CraftException('Key schedule not initialized');
        }
        $this->keySchedule->setClientApplicationTrafficSecret($secret);
    }

    // === Key Management ===

    public function updateDecryptionKeys(string $key, string $iv): void
    {
        $this->currentDecryptionKeys = ['key' => $key, 'iv' => $iv];
    }

    public function updateEncryptionKeys(string $key, string $iv): void
    {
        $this->currentEncryptionKeys = ['key' => $key, 'iv' => $iv];
    }

    public function resetReadSequenceNumber(): void
    {
        $this->readSequenceNumber = 0;
    }

    public function resetWriteSequenceNumber(): void
    {
        $this->writeSequenceNumber = 0;
    }

    // === PSK / Session Management ===
    /**
     * Add a PSK to be offered in ClientHello
     */
    public function addOfferedPsk(PreSharedKey $psk): void
    {
        $this->offeredPsks[] = $psk;
    }

    /**
     * Set PSKs to be offered in ClientHello
     * @param PreSharedKey[] $psks
     */
    public function setOfferedPsks(array $psks): void
    {
        $this->offeredPsks = $psks;
    }

    /**
     * Get all offered PSKs
     *
     * @return PreSharedKey[]
     */
    public function getOfferedPsks(): array
    {
        return $this->offeredPsks;
    }

    /**
     * Set the selected PSK (after server chooses one)
     */
    public function setSelectedPsk(PreSharedKey $psk, int $index): void
    {
        $this->selectedPsk = $psk;
        $this->selectedPskIndex = $index;
        $this->isResuming = true;
    }

    /**
     * Get selected PSK
     */
    public function getSelectedPsk(): ?PreSharedKey
    {
        return $this->selectedPsk;
    }

    /**
     * Get selected PSK index
     */
    public function getSelectedPskIndex(): ?int
    {
        return $this->selectedPskIndex;
    }

    /**
     * Check if this is a PSK resumption handshake
     */
    public function isResuming(): bool
    {
        return $this->isResuming;
    }

    /**
     * Set resumption flag
     */
    public function setIsResuming(bool $resuming): void
    {
        $this->isResuming = $resuming;
    }

    /**
     * Set PSK binder calculator
     */
    public function setPskBinderCalculator(PskBinderCalculator $calculator): void
    {
        $this->pskBinderCalculator = $calculator;
    }

    /**
     * Get PSK binder calculator
     */
    public function getPskBinderCalculator(): PskBinderCalculator
    {
        if ($this->pskBinderCalculator === null) {
            throw new CraftException('PSK binder calculator not initialized');
        }

        return $this->pskBinderCalculator;
    }

    /**
     * Check if any PSKs are configured
     */
    public function hasPsk(): bool
    {
        return !empty($this->offeredPsks) || $this->selectedPsk !== null;
    }

    /**
     * Add session ticket metadata (for obfuscated age calculation)
     */
    public function addSessionTicket(SessionTicket $ticket): void
    {
        $this->sessionTickets[] = $ticket;
    }

    /**
     * Get all session tickets
     *
     * @return SessionTicket[]
     */
    public function getSessionTickets(): array
    {
        return $this->sessionTickets;
    }

    /**
     * Set resumption secret
     */
    public function setResumptionSecret(string $secret): void
    {
        $this->resumptionSecret = $secret;
    }

    /**
     * Get resumption secret
     */
    public function getResumptionSecret(): ?string
    {
        return $this->resumptionSecret;
    }

    public function deriveResumptionSecret(string $ticketNonce): string
    {
        $keySchedule = $this->getKeySchedule();
        $resumptionMasterSecret = $keySchedule->deriveResumptionMasterSecret();
        $this->resumptionSecret = $keySchedule->deriveResumptionSecret($resumptionMasterSecret, $ticketNonce);

        return $this->resumptionSecret;
    }

    /**
     * Set PSK key exchange modes from client
     */
    public function setPskKeyExchangeModes(array $modes): void
    {
        $this->pskKeyExchangeModes = $modes;
    }

    /**
     * Get PSK key exchange modes
     *
     * @return int[]
     */
    public function getPskKeyExchangeModes(): array
    {
        return $this->pskKeyExchangeModes;
    }

    /**
     * Check if client supports PSK with (EC)DHE
     */
    public function supportsPskDhe(): bool
    {
        return in_array(PskKeyExchangeModesExtension::PSK_DHE_KE, $this->pskKeyExchangeModes, true);
    }

    /**
     * Check if client supports PSK-only mode
     */
    public function supportsPskOnly(): bool
    {
        return in_array(PskKeyExchangeModesExtension::PSK_KE, $this->pskKeyExchangeModes, true);
    }

    // === KeyUpdateMessage Response Flag ===
    private bool $keyUpdateResponseRequired = false;

    public function setKeyUpdateResponseRequired(bool $required): void
    {
        $this->keyUpdateResponseRequired = $required;
    }

    public function isKeyUpdateResponseRequired(): bool
    {
        return $this->keyUpdateResponseRequired;
    }

    public function setKeyPairForGroup(NamedGroup $group, KeyPair $keyPair): void
    {
        $this->keyPairs[$group->getName()] = $keyPair;
    }

    public function getKeyPairForGroup(NamedGroup $group): ?KeyPair
    {
        return $this->keyPairs[$group->getName()] ?? null;
    }

    public function setHandshakeComplete(bool $complete): void
    {
        $this->handshakeComplete = $complete;
    }
}
