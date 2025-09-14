<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\ECDHKeyExchange;
use Php\TlsCraft\Crypto\KeySchedule;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Protocol\Version;

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

    // Certificate chain
    private array $certificateChain = [];
    private $privateKey = null;

    // Handshake transcript
    private array $handshakeMessages = [];

    public function __construct(
        private bool $isClient,
        Version $version = Version::TLS_1_3
    ) {
        $this->negotiatedVersion = $version;
    }

    // === Getters ===

    public function isClient(): bool
    {
        return $this->isClient;
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

    public function addHandshakeMessage(HandshakeMessage $message): void
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
}