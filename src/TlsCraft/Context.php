<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Crypto\{CipherSuite, ECDHKeyExchange, KeySchedule, KeyShare, RandomGenerator, SignatureScheme};
use Php\TlsCraft\Exceptions\{CraftException, ProtocolViolationException};
use Php\TlsCraft\Extensions\Extension;
use Php\TlsCraft\Messages\{ClientHello, Message, ServerHello};
use Php\TlsCraft\Protocol\Version;

/**
 * Updated Context with missing methods
 */
class Context
{
    private Version $negotiatedVersion;
    private ?CipherSuite $negotiatedCipherSuite = null;
    private ?SignatureScheme $negotiatedSignatureScheme = null;
    private array $clientExtensions = [];
    private array $serverExtensions = [];

    // Crypto state
    private ?KeySchedule $keySchedule = null;
    private ?array $clientKeyPair = null;
    private ?array $serverKeyPair = null;
    private ?string $sharedSecret = null;

    // Random values
    private ?string $clientRandom = null;
    private ?string $serverRandom = null;

    // Certificate chain and private key
    private array $certificateChain = [];
    private $privateKey = null;

    // Handshake transcript
    private array $handshakeMessages = [];
    private KeyShare $keyShare;
    private string $requestedServerName;
    private array $clientOfferedProtocols;
    private string $selectedProtocol;
    private mixed $serverKeyShare;
    private bool $serverNameAcknowledged;
    private array $serverSupportedGroups;
    private \OpenSSLAsymmetricKey $peerPublicKey;
    private string $certificateRequestContext;
    private bool $certificateVerified;
    private bool $handshakeComplete;

    private array $currentDecryptionKeys = [];
    private array $currentEncryptionKeys = [];
    private int $readSequenceNumber = 0;
    private int $writeSequenceNumber = 0;


    public function __construct(
        private bool   $isClient,
        private Config $config,
        Version        $version = Version::TLS_1_3
    )
    {
        $this->negotiatedVersion = $version;
    }

    // === Getters ===

    public function getConfig(): Config
    {
        return $this->config;
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
            $this->clientRandom = RandomGenerator::generateClientRandom();
        }
        return $this->clientRandom;
    }

    public function getServerRandom(): ?string
    {
        return $this->serverRandom;
    }

    public function getSharedSecret(): ?string
    {
        return $this->sharedSecret;
    }

    public function getCertificateChain(): array
    {
        return $this->certificateChain;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    // === Setters ===

    public function setNegotiatedCipherSuite(CipherSuite $cipherSuite): void
    {
        $this->negotiatedCipherSuite = $cipherSuite;
        $this->keySchedule = new KeySchedule($cipherSuite);
    }

    public function setNegotiatedSignatureScheme(SignatureScheme $scheme): void
    {
        $this->negotiatedSignatureScheme = $scheme;
    }

    public function setClientRandom(string $random): void
    {
        if (strlen($random) !== 32) {
            throw new ProtocolViolationException("Client random must be 32 bytes");
        }
        $this->clientRandom = $random;
    }

    public function setServerRandom(string $random): void
    {
        if (strlen($random) !== 32) {
            throw new ProtocolViolationException("Server random must be 32 bytes");
        }
        $this->serverRandom = $random;
    }

    public function setCertificateChain(array $chain): void
    {
        $this->certificateChain = $chain;
    }

    public function setPrivateKey($privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    // === Key Exchange ===

    public function generateKeyPair(): void
    {
        $keyPair = ECDHKeyExchange::generateKeyPair();

        if ($this->isClient) {
            $this->clientKeyPair = $keyPair;
        } else {
            $this->serverKeyPair = $keyPair;
        }
    }

    public function setPeerKeyShare(string $publicKeyPoint): void
    {
        if ($this->isClient && $this->clientKeyPair) {
            $this->sharedSecret = ECDHKeyExchange::computeSharedSecret(
                $this->clientKeyPair['private_key'],
                $publicKeyPoint
            );
        } elseif (!$this->isClient && $this->serverKeyPair) {
            $this->sharedSecret = ECDHKeyExchange::computeSharedSecret(
                $this->serverKeyPair['private_key'],
                $publicKeyPoint
            );
        }
    }

    public function getOwnPublicKeyPoint(): ?string
    {
        if ($this->isClient && $this->clientKeyPair) {
            return $this->clientKeyPair['public_key_point'];
        } elseif (!$this->isClient && $this->serverKeyPair) {
            return $this->serverKeyPair['public_key_point'];
        }
        return null;
    }

    // === Extensions ===

    public function addClientExtension(Extension $extension): void
    {
        $this->clientExtensions[] = $extension;
    }

    public function addServerExtension(Extension $extension): void
    {
        $this->serverExtensions[] = $extension;
    }

    public function getClientExtensions(): array
    {
        return $this->clientExtensions;
    }

    public function getServerExtensions(): array
    {
        return $this->serverExtensions;
    }

    public function findExtension(int $type, bool $fromServer = false): ?Extension
    {
        $extensions = $fromServer ? $this->serverExtensions : $this->clientExtensions;

        foreach ($extensions as $extension) {
            if ($extension->type === $type) {
                return $extension;
            }
        }

        return null;
    }

    // === Handshake Transcript ===

    public function addHandshakeMessage(Message $message): void
    {
        $wireFormat = $message->toWire();
        $this->handshakeMessages[] = $wireFormat;

        if ($this->keySchedule) {
            $this->keySchedule->addHandshakeMessage($wireFormat);
        }
    }

    public function getHandshakeTranscript(): string
    {
        return implode('', $this->handshakeMessages);
    }

    // === Key Derivation ===

    public function deriveHandshakeSecrets(): void
    {
        if (!$this->keySchedule || !$this->sharedSecret) {
            throw new CraftException("Cannot derive handshake secrets: missing key schedule or shared secret");
        }

        $this->keySchedule->deriveHandshakeSecret($this->sharedSecret);
    }

    public function deriveApplicationSecrets(): void
    {
        if (!$this->keySchedule) {
            throw new CraftException("Cannot derive application secrets: missing key schedule");
        }

        $this->keySchedule->deriveMasterSecret();
    }

    public function getHandshakeKeys(bool $forClient): array
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientHandshakeTrafficSecret() :
            $this->keySchedule->getServerHandshakeTrafficSecret();

        return $this->keySchedule->deriveApplicationKeys($trafficSecret);
    }

    public function getApplicationKeys(bool $forClient): array
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientApplicationTrafficSecret() :
            $this->keySchedule->getServerApplicationTrafficSecret();

        return $this->keySchedule->deriveApplicationKeys($trafficSecret);
    }

    public function getFinishedData(bool $forClient): string
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }

        $trafficSecret = $forClient ?
            $this->keySchedule->getClientHandshakeTrafficSecret() :
            $this->keySchedule->getServerHandshakeTrafficSecret();

        $finishedKey = $this->keySchedule->getFinishedKey($trafficSecret);
        return $this->keySchedule->calculateFinishedData($finishedKey);
    }

    // === Traffic Key Updates ===

    public function updateTrafficKeys(): void
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }

        // Update both client and server traffic secrets
        $clientSecret = $this->keySchedule->getClientApplicationTrafficSecret();
        $serverSecret = $this->keySchedule->getServerApplicationTrafficSecret();

        $newClientSecret = $this->keySchedule->updateTrafficSecret($clientSecret);
        $newServerSecret = $this->keySchedule->updateTrafficSecret($serverSecret);

        // Derive new keys from updated secrets
        $clientKeys = $this->keySchedule->deriveApplicationKeys($newClientSecret);
        $serverKeys = $this->keySchedule->deriveApplicationKeys($newServerSecret);

        // Store updated secrets (in a real implementation, these would update the key schedule)
        // For now, this is a placeholder for the key update process
    }

    // === Validation ===

    public function validateNegotiation(): void
    {
        if ($this->negotiatedCipherSuite === null) {
            throw new ProtocolViolationException("No cipher suite negotiated");
        }

        if ($this->clientRandom === null || $this->serverRandom === null) {
            throw new ProtocolViolationException("Missing client or server random");
        }

        if ($this->sharedSecret === null) {
            throw new ProtocolViolationException("No shared secret established");
        }
    }

    // === Cipher Suite Negotiation ===

    public function selectCipherSuite(array $clientSuites, array $serverSuites): ?CipherSuite
    {
        foreach ($serverSuites as $serverSuite) {
            if (in_array($serverSuite->value, $clientSuites)) {
                $this->setNegotiatedCipherSuite($serverSuite);
                return $serverSuite;
            }
        }

        return null;
    }

    // === Extension Processing ===

    public function processClientHello(ClientHello $clientHello): void
    {
        $this->setClientRandom($clientHello->random);

        foreach ($clientHello->extensions as $extension) {
            $this->addClientExtension($extension);
        }

        // Process supported versions extension
        $supportedVersions = $this->findExtension(43); // supported_versions
        if ($supportedVersions) {
            // In a real implementation, we'd parse the extension data
            $this->negotiatedVersion = Version::TLS_1_3;
        }

        // Process key share extension
        $keyShare = $this->findExtension(51); // key_share
        if ($keyShare) {
            // In a real implementation, we'd parse the key share data
            // For now, just generate our own key pair
            $this->generateKeyPair();
        }
    }

    public function processServerHello(ServerHello $serverHello): void
    {
        $this->setServerRandom($serverHello->random);
        $this->setNegotiatedCipherSuite(CipherSuite::from($serverHello->cipherSuite));

        foreach ($serverHello->extensions as $extension) {
            $this->addServerExtension($extension);
        }

        // Process key share extension
        $keyShare = $this->findExtension(51, true); // key_share from server
        if ($keyShare) {
            // In a real implementation, we'd parse the server's public key
            // For now, simulate receiving the server's key share
        }
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

    public function getRequestedServerName(): string
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

    public function getSelectedProtocol(): string
    {
        return $this->selectedProtocol;
    }

    public function setServerKeyShare(mixed $serverKeyShare)
    {
        $this->serverKeyShare = $serverKeyShare;
    }

    public function getServerKeyShare(): mixed
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

    public function setPeerPublicKey(\OpenSSLAsymmetricKey $publicKey)
    {
        $this->peerPublicKey = $publicKey;
    }

    public function getPeerPublicKey(): \OpenSSLAsymmetricKey
    {
        return $this->peerPublicKey;
    }

    public function addIntermediateCertificate(array $parsedCert)
    {
        $this->certificateChain[] = $parsedCert;
    }

    public function setCertificateRequestContext(string $context)
    {
        $this->certificateRequestContext = $context;
    }

    public function getCertificateRequestContext()
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

    public function getTranscriptHash(): string
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }

        $transcriptData = $this->getHandshakeTranscript();
        $hashAlgorithm = $this->negotiatedCipherSuite?->getHashAlgorithm() ?? 'sha256';

        return hash($hashAlgorithm, $transcriptData, true);
    }

    public function hasApplicationSecrets(): bool
    {
        return $this->keySchedule && $this->keySchedule->hasApplicationSecrets();
    }

    public function isHandshakeComplete(): bool
    {
        return $this->handshakeComplete;
    }


// === Application Traffic Secret Management ===

    public function getServerApplicationTrafficSecret(): string
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }
        return $this->keySchedule->getServerApplicationTrafficSecret();
    }

    public function getClientApplicationTrafficSecret(): string
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }
        return $this->keySchedule->getClientApplicationTrafficSecret();
    }

    public function setServerApplicationTrafficSecret(string $secret): void
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
        }
        $this->keySchedule->setServerApplicationTrafficSecret($secret);
    }

    public function setClientApplicationTrafficSecret(string $secret): void
    {
        if (!$this->keySchedule) {
            throw new CraftException("Key schedule not initialized");
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

    // === KeyUpdate Response Flag ===
    private bool $keyUpdateResponseRequired = false;

    public function setKeyUpdateResponseRequired(bool $required): void
    {
        $this->keyUpdateResponseRequired = $required;
    }

    public function isKeyUpdateResponseRequired(): bool
    {
        return $this->keyUpdateResponseRequired;
    }
}
