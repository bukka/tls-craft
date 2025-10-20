<?php

namespace Php\TlsCraft;

use Closure;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Handshake\ClientHelloExtensionProviders;
use Php\TlsCraft\Handshake\EncryptedExtensionsProviders;
use Php\TlsCraft\Handshake\ExtensionProviders\AlpnExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\KeyShareExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\ServerNameExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SignatureAlgorithmsProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SupportedGroupsProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SupportedVersionsProvider;
use Php\TlsCraft\Handshake\ServerHelloExtensionProviders;
use Php\TlsCraft\State\ProtocolValidator;

class Config
{
    // Protocol parameters - set at construction, used by extensions (immutable)
    private array $supportedVersions;
    private array $cipherSuites;
    private array $supportedGroups;
    private array $signatureAlgorithms;
    private ?string $serverName = null;
    private array $supportedProtocols = [];

    // Extension providers (public for direct access)
    private ClientHelloExtensionProviders $clientHelloExtensions;
    private ServerHelloExtensionProviders $serverHelloExtensions;
    private EncryptedExtensionsProviders $encryptedExtensions;

    // Runtime configuration (mutable)
    private ?Closure $onStateChange = null;
    private ?Closure $onKeyUpdate = null;
    private ?Closure $onAlert = null;
    private bool $allowProtocolViolations = false;
    private ?ProtocolValidator $customValidator = null;
    private array $connectionOptions = [];

    // Certificate validation options
    private bool $requireTrustedCertificates = false;
    private bool $allowSelfSignedCertificates = true;
    private bool $validateCertificateExpiry = true;
    private bool $validateCertificatePurpose = true;
    private bool $validateHostname = true;
    private ?string $customCaPath = null;
    private ?string $customCaFile = null;

    public function __construct(
        ?array $supportedVersions = null,
        ?array $cipherSuites = null,
        ?array $supportedGroups = null,
        ?array $signatureAlgorithms = null,
        ?string $serverName = null,
        ?array $supportedProtocols = null,
    ) {
        // Set immutable protocol parameters
        $this->supportedVersions = $supportedVersions ?? ['TLS 1.3'];

        $this->cipherSuites = $cipherSuites ?? [
            CipherSuite::TLS_AES_128_GCM_SHA256->value,
            CipherSuite::TLS_AES_256_GCM_SHA384->value,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256->value,
        ];

        $this->supportedGroups = $supportedGroups ?? ['P-256', 'P-384', 'P-521'];

        // Use signature algorithm names instead of values
        $this->signatureAlgorithms = $signatureAlgorithms ?? [
            'rsa_pkcs1_sha256',
            'rsa_pkcs1_sha384',
            'rsa_pkcs1_sha512',
            'ecdsa_secp256r1_sha256',
            'ecdsa_secp384r1_sha384',
            'ecdsa_secp521r1_sha512',
            'rsa_pss_rsae_sha256',
            'rsa_pss_rsae_sha384',
            'rsa_pss_rsae_sha512',
        ];

        $this->serverName = $serverName;
        $this->supportedProtocols = $supportedProtocols ?? [];

        // Initialize extension providers
        $this->clientHelloExtensions = new ClientHelloExtensionProviders();
        $this->serverHelloExtensions = new ServerHelloExtensionProviders();
        $this->encryptedExtensions = new EncryptedExtensionsProviders();

        // Add default extensions
        $this->addDefaultExtensions();
    }

    public function getClientHelloExtensions(): ClientHelloExtensionProviders
    {
        return $this->clientHelloExtensions;
    }

    public function getEncryptedExtensions(): EncryptedExtensionsProviders
    {
        return $this->encryptedExtensions;
    }

    public function getServerHelloExtensions(): ServerHelloExtensionProviders
    {
        return $this->serverHelloExtensions;
    }

    // Getters for immutable protocol parameters
    public function getSupportedVersions(): array
    {
        return $this->supportedVersions;
    }

    public function getCipherSuites(): array
    {
        return $this->cipherSuites;
    }

    public function getSupportedGroups(): array
    {
        return $this->supportedGroups;
    }

    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }

    public function getServerName(): ?string
    {
        return $this->serverName;
    }

    public function getSupportedProtocols(): array
    {
        return $this->supportedProtocols;
    }

    // Getters/setters for mutable runtime configuration
    public function getOnStateChange(): ?Closure
    {
        return $this->onStateChange;
    }

    public function setOnStateChange(?Closure $callback): self
    {
        $this->onStateChange = $callback;

        return $this;
    }

    public function getOnKeyUpdate(): ?Closure
    {
        return $this->onKeyUpdate;
    }

    public function setOnKeyUpdate(?Closure $callback): self
    {
        $this->onKeyUpdate = $callback;

        return $this;
    }

    public function getOnAlert(): ?Closure
    {
        return $this->onAlert;
    }

    public function setOnAlert(?Closure $callback): self
    {
        $this->onAlert = $callback;

        return $this;
    }

    public function isAllowProtocolViolations(): bool
    {
        return $this->allowProtocolViolations;
    }

    public function setAllowProtocolViolations(bool $allow): self
    {
        $this->allowProtocolViolations = $allow;

        return $this;
    }

    public function getCustomValidator(): ?ProtocolValidator
    {
        return $this->customValidator;
    }

    public function setCustomValidator(?ProtocolValidator $validator): self
    {
        $this->customValidator = $validator;

        return $this;
    }

    public function getConnectionOptions(): array
    {
        return $this->connectionOptions;
    }

    public function setConnectionOptions(array $options): self
    {
        $this->connectionOptions = $options;

        return $this;
    }

    // Certificate validation getters/setters
    public function isRequireTrustedCertificates(): bool
    {
        return $this->requireTrustedCertificates;
    }

    public function setRequireTrustedCertificates(bool $require): self
    {
        $this->requireTrustedCertificates = $require;

        return $this;
    }

    public function isAllowSelfSignedCertificates(): bool
    {
        return $this->allowSelfSignedCertificates;
    }

    public function setAllowSelfSignedCertificates(bool $allow): self
    {
        $this->allowSelfSignedCertificates = $allow;

        return $this;
    }

    public function isValidateCertificateExpiry(): bool
    {
        return $this->validateCertificateExpiry;
    }

    public function setValidateCertificateExpiry(bool $validate): self
    {
        $this->validateCertificateExpiry = $validate;

        return $this;
    }

    public function isValidateCertificatePurpose(): bool
    {
        return $this->validateCertificatePurpose;
    }

    public function setValidateCertificatePurpose(bool $validate): self
    {
        $this->validateCertificatePurpose = $validate;

        return $this;
    }

    public function isValidateHostname(): bool
    {
        return $this->validateHostname;
    }

    public function setValidateHostname(bool $validate): self
    {
        $this->validateHostname = $validate;

        return $this;
    }

    public function getCustomCaPath(): ?string
    {
        return $this->customCaPath;
    }

    public function setCustomCaPath(?string $path): self
    {
        $this->customCaPath = $path;

        return $this;
    }

    public function getCustomCaFile(): ?string
    {
        return $this->customCaFile;
    }

    public function setCustomCaFile(?string $file): self
    {
        $this->customCaFile = $file;

        return $this;
    }

    // Convenience methods for testing
    public function forTesting(): self
    {
        return $this->setAllowSelfSignedCertificates(true)
            ->setRequireTrustedCertificates(false)
            ->setValidateCertificateExpiry(false)
            ->setValidateCertificatePurpose(false)
            ->setValidateHostname(false);
    }

    public function forProduction(): self
    {
        return $this->setAllowSelfSignedCertificates(false)
            ->setRequireTrustedCertificates(true)
            ->setValidateCertificateExpiry(true)
            ->setValidateCertificatePurpose(true)
            ->setValidateHostname(true);
    }

    public function withCustomCa(string $caPath = null, string $caFile = null): self
    {
        if ($caPath !== null) {
            $this->setCustomCaPath($caPath);
        }
        if ($caFile !== null) {
            $this->setCustomCaFile($caFile);
        }

        return $this->setRequireTrustedCertificates(true)
            ->setAllowSelfSignedCertificates(false);
    }

    // Original extension setup methods - kept intact
    private function addDefaultExtensions(): void
    {
        $this->addRequiredClientExtensions();
        $this->addServerExtensions();
    }

    private function addRequiredClientExtensions(): void
    {
        // MANDATORY TLS 1.3 extensions
        $this->clientHelloExtensions->addMany([
            new SupportedVersionsProvider($this->supportedVersions),
            new SupportedGroupsProvider($this->supportedGroups),
            new KeyShareExtensionProvider($this->supportedGroups),
            new SignatureAlgorithmsProvider($this->signatureAlgorithms),
        ]);
        if (null !== $this->serverName) {
            $this->addServerName($this->serverName);
        }
        if (!empty($this->supportedProtocols)) {
            $this->addAlpn($this->supportedProtocols);
        }
    }

    public function addServerName(string $serverName): void
    {
        $this->clientHelloExtensions->add(
            new ServerNameExtensionProvider($serverName),
        );
    }

    public function addAlpn(?array $protocols = null): void
    {
        if (null !== $protocols) {
            $this->supportedProtocols = $protocols;
        }
        $this->clientHelloExtensions->add(
            new AlpnExtensionProvider($this->supportedProtocols),
        );
    }

    public function addServerExtensions(): void
    {
        $this->addServerHelloExtensions();
        $this->addServerEncryptedExtensions();
    }

    private function addServerHelloExtensions(): void
    {
        // Server HelloExtensions - typically echo client's selections
        $this->serverHelloExtensions->addMany([
            new SupportedVersionsProvider($this->supportedVersions),
            new KeyShareExtensionProvider($this->supportedGroups),
        ]);
    }

    public function addServerEncryptedExtensions(): void
    {
        // Server EncryptedExtensions - Add extensions for server name acknowledgement (empty server name) and ALPN
        $this->encryptedExtensions->add(new ServerNameExtensionProvider());
        $this->encryptedExtensions->add(new AlpnExtensionProvider($this->supportedProtocols));
    }

    public function hasCustomValidator()
    {
        return $this->customValidator !== null;
    }
}
