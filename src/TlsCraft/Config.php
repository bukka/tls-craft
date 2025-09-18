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
use Php\TlsCraft\Handshake\ExtensionProviders\SupportedVersionsProvider;
use Php\TlsCraft\Handshake\ServerHelloExtensionProviders;
use Php\TlsCraft\Protocol\Version;
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
    private bool $requireTrustedCertificates = false;
    private bool $allowSelfSignedCertificates = true;

    public function __construct(
        ?array  $supportedVersions = null,
        ?array  $cipherSuites = null,
        ?array  $supportedGroups = null,
        ?array  $signatureAlgorithms = null,
        ?string $serverName = null,
        ?array  $supportedProtocols = null
    )
    {
        // Set immutable protocol parameters
        $this->supportedVersions = $supportedVersions ?? [Version::TLS_1_3];

        $this->cipherSuites = $cipherSuites ?? [
            CipherSuite::TLS_AES_128_GCM_SHA256->value,
            CipherSuite::TLS_AES_256_GCM_SHA384->value,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256->value,
        ];

        $this->supportedGroups = $supportedGroups ?? ['P-256', 'P-384', 'P-521'];

        $this->signatureAlgorithms = $signatureAlgorithms ?? [
            SignatureScheme::RSA_PKCS1_SHA256->value,
            SignatureScheme::RSA_PKCS1_SHA384->value,
            SignatureScheme::ECDSA_SECP256R1_SHA256->value,
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

    // Convenience methods for testing
    public function forTesting(): self
    {
        return $this->setAllowSelfSignedCertificates(true)
            ->setRequireTrustedCertificates(false);
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
            new KeyShareExtensionProvider($this->supportedGroups),
            new SignatureAlgorithmsProvider($this->signatureAlgorithms),
        ]);
        if (!is_null($this->serverName)) {
            $this->addServerName($this->serverName);
        }
        if (!empty($this->supportedProtocols)) {
            $this->addAlpn($this->supportedProtocols);
        }
    }

    public function addServerName(string $serverName): void
    {
        $this->clientHelloExtensions->add(
            new ServerNameExtensionProvider($serverName)
        );
    }

    public function addAlpn(?array $protocols = null): void
    {
        if (!is_null($protocols)) {
            $this->supportedProtocols = $protocols;
        }
        $this->clientHelloExtensions->add(
            new AlpnExtensionProvider($this->supportedProtocols)
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
