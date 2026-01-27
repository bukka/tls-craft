<?php

namespace Php\TlsCraft;

use Closure;
use InvalidArgumentException;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Handshake\ClientHelloExtensionProviders;
use Php\TlsCraft\Handshake\EncryptedExtensionsProviders;
use Php\TlsCraft\Handshake\ExtensionProviders\AlpnExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\EarlyDataExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\KeyShareExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\PreSharedKeyExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\PskKeyExchangeModesExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\ServerNameExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SignatureAlgorithmsExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SupportedGroupsExtensionProvider;
use Php\TlsCraft\Handshake\ExtensionProviders\SupportedVersionsExtensionProvider;
use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;
use Php\TlsCraft\Handshake\ServerHelloExtensionProviders;
use Php\TlsCraft\Protocol\EarlyDataServerMode;
use Php\TlsCraft\Session\PlainSessionTicketSerializer;
use Php\TlsCraft\Session\PreSharedKey;
use Php\TlsCraft\Session\PskResolver;
use Php\TlsCraft\Session\SessionStorage;
use Php\TlsCraft\Session\SessionTicketSerializer;
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

    // Certificate configuration (used for both client and server)
    private ?string $certificateFile = null;
    private ?string $privateKeyFile = null;
    private ?string $privateKeyPassphrase = null;

    // Certificate validation options
    private bool $requireTrustedCertificates = false;
    private bool $allowSelfSignedCertificates = true;
    private bool $validateCertificateExpiry = true;
    private bool $validateCertificatePurpose = true;
    private bool $validateHostname = true;
    private ?string $customCaPath = null;
    private ?string $customCaFile = null;

    // Client certificate request (server-side only)
    private bool $requestClientCertificate = false;

    // === PSK / Session Resumption Configuration ===

    // Enable/disable session resumption
    private bool $enableSessionResumption = true;

    // Session ticket lifetime in seconds (default 24 hours)
    private int $sessionLifetimeSeconds = 86400;

    // Maximum early data size (0 = disabled, for future 0-RTT support)
    private int $maxEarlyDataSize = 0;

    // PSK key exchange modes (default: PSK with (EC)DHE)
    private array $pskKeyExchangeModes = [PskKeyExchangeModesExtension::PSK_DHE_KE];

    // Session storage backend (null = no storage, tickets won't be saved)
    private ?SessionStorage $sessionStorage = null;
    // Session ticket serializer (null = use default serializer)
    private ?SessionTicketSerializer $sessionTicketSerializer = null;

    // External PSKs (manually configured pre-shared keys)
    /** @var PreSharedKey[] */
    private array $externalPsks = [];

    // Callback for session ticket received (client-side)
    private ?Closure $onSessionTicket = null;

    // Callback for PSK selection (server-side)
    private ?Closure $onPskSelection = null;

    // Early data (0-RTT) client configuration
    private bool $enableEarlyData = false;
    private ?string $earlyData = null;
    private ?Closure $onEarlyDataRejected = null;

    // Early data (0-RTT) server configuration
    private EarlyDataServerMode $earlyDataServerMode = EarlyDataServerMode::REJECT;
    private ?Closure $earlyDataServerModeCallback = null;

    public function __construct(
        ?array $supportedVersions = null,
        ?array $cipherSuites = null,
        ?array $supportedGroups = null,
        ?array $signatureAlgorithms = null,
        ?string $serverName = null,
        ?array $supportedProtocols = null,
        // Client early data parameters
        bool $enableEarlyData = false,
        ?string $earlyData = null,
        // Server early data parameters
        int $maxEarlyDataSize = 0,
        EarlyDataServerMode $earlyDataServerMode = EarlyDataServerMode::REJECT,
    ) {
        // Set immutable protocol parameters
        $this->supportedVersions = $supportedVersions ?? ['TLS 1.3'];

        $this->cipherSuites = $cipherSuites ?? [
            CipherSuite::TLS_AES_128_GCM_SHA256->value,
            CipherSuite::TLS_AES_256_GCM_SHA384->value,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256->value,
        ];

        $this->supportedGroups = $supportedGroups ?? ['P-256', 'P-384', 'P-521', 'X25519'];

        $this->signatureAlgorithms = $signatureAlgorithms ?? [
            'ecdsa_secp256r1_sha256',
            'ecdsa_secp384r1_sha384',
            'ecdsa_secp521r1_sha512',
            'rsa_pss_rsae_sha256',
            'rsa_pss_rsae_sha384',
            'rsa_pss_rsae_sha512',
            'rsa_pkcs1_sha256',
            'rsa_pkcs1_sha384',
            'rsa_pkcs1_sha512',
        ];

        $this->serverName = $serverName;
        $this->supportedProtocols = $supportedProtocols ?? [];

        // Set early data configuration BEFORE initializing extensions
        $this->enableEarlyData = $enableEarlyData;
        $this->earlyData = $earlyData;
        $this->maxEarlyDataSize = $maxEarlyDataSize;
        $this->earlyDataServerMode = $earlyDataServerMode;

        // Initialize extension providers
        $this->clientHelloExtensions = new ClientHelloExtensionProviders();
        $this->serverHelloExtensions = new ServerHelloExtensionProviders();
        $this->encryptedExtensions = new EncryptedExtensionsProviders();

        // Add default extensions (will now see early data config)
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

    public function hasCustomValidator(): bool
    {
        return $this->customValidator !== null;
    }

    // === Certificate Configuration (used for both client and server) ===

    /**
     * Set certificate file path
     * - When server: this is the server certificate
     * - When client: this is the client certificate (for client authentication)
     */
    public function setCertificateFile(?string $file): self
    {
        if ($file !== null && !is_file($file)) {
            throw new InvalidArgumentException("Certificate file does not exist: {$file}");
        }

        $this->certificateFile = $file;

        return $this;
    }

    public function getCertificateFile(): ?string
    {
        return $this->certificateFile;
    }

    /**
     * Set private key file path
     * - When server: this is the server's private key
     * - When client: this is the client's private key (for client authentication)
     */
    public function setPrivateKeyFile(?string $file, ?string $passphrase = null): self
    {
        if ($file !== null && !is_file($file)) {
            throw new InvalidArgumentException("Private key file does not exist: {$file}");
        }

        $this->privateKeyFile = $file;
        $this->privateKeyPassphrase = $passphrase;

        return $this;
    }

    public function getPrivateKeyFile(): ?string
    {
        return $this->privateKeyFile;
    }

    public function getPrivateKeyPassphrase(): ?string
    {
        return $this->privateKeyPassphrase;
    }

    /**
     * Check if certificate and key are configured
     */
    public function hasCertificate(): bool
    {
        return $this->certificateFile !== null && $this->privateKeyFile !== null;
    }

    /**
     * Configure certificate and key (convenience method)
     */
    public function withCertificate(string $certFile, string $keyFile, ?string $passphrase = null): self
    {
        return $this->setCertificateFile($certFile)
            ->setPrivateKeyFile($keyFile, $passphrase);
    }

    // === Certificate Validation Options ===

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
        if ($path !== null && !is_dir($path)) {
            throw new InvalidArgumentException("CA path does not exist or is not a directory: {$path}");
        }

        $this->customCaPath = $path;

        return $this;
    }

    public function getCustomCaFile(): ?string
    {
        return $this->customCaFile;
    }

    public function setCustomCaFile(?string $file): self
    {
        if ($file !== null && !is_file($file)) {
            throw new InvalidArgumentException("CA file does not exist: {$file}");
        }

        $this->customCaFile = $file;

        return $this;
    }

    public function hasCustomCa(): bool
    {
        return $this->customCaPath !== null || $this->customCaFile !== null;
    }

    // === Client Certificate Request (Server-side) ===

    /**
     * Enable/disable requesting client certificates (server-side only)
     * When enabled on server, it will send CertificateRequest during handshake
     */
    public function setRequestClientCertificate(bool $request): self
    {
        $this->requestClientCertificate = $request;

        return $this;
    }

    public function isRequestClientCertificate(): bool
    {
        return $this->requestClientCertificate;
    }

    // === PSK / Session Resumption Configuration ===

    /**
     * Enable or disable session resumption
     */
    public function setEnableSessionResumption(bool $enable): self
    {
        $this->enableSessionResumption = $enable;

        return $this;
    }

    public function isSessionResumptionEnabled(): bool
    {
        return $this->enableSessionResumption;
    }

    /**
     * Set session ticket lifetime in seconds
     */
    public function setSessionLifetime(int $seconds): self
    {
        if ($seconds < 0) {
            throw new InvalidArgumentException('Session lifetime must be non-negative');
        }

        $this->sessionLifetimeSeconds = $seconds;

        return $this;
    }

    public function getSessionLifetime(): int
    {
        return $this->sessionLifetimeSeconds;
    }

    /**
     * Set maximum early data size (0 = disabled)
     * For future 0-RTT support
     */
    public function setMaxEarlyDataSize(int $size): self
    {
        if ($size < 0) {
            throw new InvalidArgumentException('Max early data size must be non-negative');
        }

        $this->maxEarlyDataSize = $size;

        return $this;
    }

    public function getMaxEarlyDataSize(): int
    {
        return $this->maxEarlyDataSize;
    }

    /**
     * Set PSK key exchange modes
     *
     * @param int[] $modes Array of PskKeyExchangeModesExtension constants
     */
    public function setPskKeyExchangeModes(array $modes): self
    {
        if (empty($modes)) {
            throw new InvalidArgumentException('At least one PSK key exchange mode must be specified');
        }

        $this->pskKeyExchangeModes = $modes;

        return $this;
    }

    /**
     * @return int[]
     */
    public function getPskKeyExchangeModes(): array
    {
        return $this->pskKeyExchangeModes;
    }

    /**
     * Set session storage backend
     */
    public function setSessionStorage(?SessionStorage $storage): self
    {
        $this->sessionStorage = $storage;

        return $this;
    }

    public function getSessionStorage(): ?SessionStorage
    {
        return $this->sessionStorage;
    }

    public function hasSessionStorage(): bool
    {
        return $this->sessionStorage !== null;
    }

    /**
     * Add an external PSK (manually configured pre-shared key)
     */
    public function addExternalPsk(PreSharedKey $psk): self
    {
        $this->externalPsks[] = $psk;

        return $this;
    }

    /**
     * Add external PSK by identity and secret
     */
    public function addExternalPskByIdentity(
        string $identity,
        string $secret,
        CipherSuite $cipherSuite,
    ): self {
        return $this->addExternalPsk(PreSharedKey::external($identity, $secret, $cipherSuite));
    }

    /**
     * Get all configured external PSKs
     *
     * @return PreSharedKey[]
     */
    public function getExternalPsks(): array
    {
        return $this->externalPsks;
    }

    /**
     * Check if any external PSKs are configured
     */
    public function hasExternalPsks(): bool
    {
        return !empty($this->externalPsks);
    }

    /**
     * Set callback for when session ticket is received (client-side)
     * Callback signature: function(NewSessionTicketMessage $ticket): void
     */
    public function setOnSessionTicket(?Closure $callback): self
    {
        $this->onSessionTicket = $callback;

        return $this;
    }

    public function getOnSessionTicket(): ?Closure
    {
        return $this->onSessionTicket;
    }

    /**
     * Set callback for PSK selection (server-side)
     * Callback signature: function(array $offeredIdentities): ?int
     * Should return the index of the selected PSK or null to reject all
     */
    public function setOnPskSelection(?Closure $callback): self
    {
        $this->onPskSelection = $callback;

        return $this;
    }

    public function getOnPskSelection(): ?Closure
    {
        return $this->onPskSelection;
    }

    // === Early Data (0-RTT) Client Configuration ===

    /**
     * Enable or disable early data (0-RTT)
     */
    public function setEnableEarlyData(bool $enable): self
    {
        $this->enableEarlyData = $enable;

        return $this;
    }

    /**
     * Check if early data is enabled
     */
    public function isEarlyDataEnabled(): bool
    {
        return $this->enableEarlyData;
    }

    /**
     * Set the early data to send (application data for 0-RTT)
     *
     * WARNING: Early data is NOT replay-protected. Only use for
     * idempotent requests (e.g., GET requests, safe operations).
     */
    public function setEarlyData(?string $data): self
    {
        $this->earlyData = $data;

        return $this;
    }

    /**
     * Get the early data to send
     */
    public function getEarlyData(): ?string
    {
        return $this->earlyData;
    }

    /**
     * Check if early data is configured
     */
    public function hasEarlyData(): bool
    {
        return $this->earlyData !== null && $this->earlyData !== '';
    }

    /**
     * Set callback for when early data is rejected by server
     *
     * Callback signature: function(string $earlyData): void
     *
     * The callback receives the early data that needs to be resent
     * over the regular connection.
     */
    public function setOnEarlyDataRejected(?Closure $callback): self
    {
        $this->onEarlyDataRejected = $callback;

        return $this;
    }

    /**
     * Get early data rejection callback
     */
    public function getOnEarlyDataRejected(): ?Closure
    {
        return $this->onEarlyDataRejected;
    }

    /**
     * Configure early data with convenience method
     *
     * @param string       $data       The data to send as 0-RTT
     * @param Closure|null $onRejected Callback if server rejects early data
     */
    public function withEarlyData(string $data, ?Closure $onRejected = null): self
    {
        return $this->setEnableEarlyData(true)
            ->setEarlyData($data)
            ->setOnEarlyDataRejected($onRejected);
    }

    /**
     * Disable early data
     */
    public function withoutEarlyData(): self
    {
        return $this->setEnableEarlyData(false)
            ->setEarlyData(null)
            ->setOnEarlyDataRejected(null);
    }

    // === Early Data (0-RTT) Server Configuration ===
    //
    // RFC 8446 Section 4.2.10 defines three server behaviors:
    //
    // 1. ACCEPT: Include early_data extension in EncryptedExtensions,
    //    decrypt early data with client_early_traffic_secret, process it.
    //
    // 2. REJECT: Ignore extension, return regular 1-RTT response.
    //    Skip early data by trying to decrypt with handshake key,
    //    discard failures (up to max_early_data_size).
    //
    // 3. HELLO_RETRY_REQUEST: Send HRR, client must retry without early_data.
    //    Skip all records with external content type "application_data".

    /**
     * Set server early data mode
     *
     * @param EarlyDataServerMode $mode How server handles early data
     */
    public function setEarlyDataServerMode(EarlyDataServerMode $mode): self
    {
        $this->earlyDataServerMode = $mode;

        return $this;
    }

    /**
     * Get server early data mode
     */
    public function getEarlyDataServerMode(): EarlyDataServerMode
    {
        return $this->earlyDataServerMode;
    }

    /**
     * Set callback for per-connection early data mode decision
     *
     * Callback signature: function(Context $context): EarlyDataServerMode
     *
     * This allows dynamic decisions based on:
     * - The PSK identity being used
     * - Anti-replay state (single-use ticket tracking)
     * - Rate limiting
     * - Application-specific validation
     *
     * If set, this callback overrides the static mode.
     */
    public function setEarlyDataServerModeCallback(?Closure $callback): self
    {
        $this->earlyDataServerModeCallback = $callback;

        return $this;
    }

    /**
     * Get server mode callback
     */
    public function getEarlyDataServerModeCallback(): ?Closure
    {
        return $this->earlyDataServerModeCallback;
    }

    /**
     * Determine server early data mode for a connection
     *
     * Uses callback if set, otherwise returns static mode.
     */
    public function determineEarlyDataMode(Context $context): EarlyDataServerMode
    {
        if ($this->earlyDataServerModeCallback !== null) {
            return ($this->earlyDataServerModeCallback)($context);
        }

        return $this->earlyDataServerMode;
    }

    /**
     * Configure server to accept early data
     *
     * WARNING: Early data is vulnerable to replay attacks!
     * Only use if your application can handle replayed requests safely.
     */
    public function withEarlyDataAcceptance(): self
    {
        return $this->setEarlyDataServerMode(EarlyDataServerMode::ACCEPT);
    }

    /**
     * Configure server to reject early data (default, safest)
     */
    public function withEarlyDataRejection(): self
    {
        return $this->setEarlyDataServerMode(EarlyDataServerMode::REJECT);
    }

    /**
     * Configure server to reject early data with HelloRetryRequest
     */
    public function withEarlyDataHelloRetryRequest(): self
    {
        return $this->setEarlyDataServerMode(EarlyDataServerMode::HELLO_RETRY_REQUEST);
    }

    // === Convenience Methods for Common Configurations ===

    /**
     * Configure for testing environment (permissive validation)
     */
    public function forTesting(): self
    {
        return $this->setAllowSelfSignedCertificates(true)
            ->setRequireTrustedCertificates(false)
            ->setValidateCertificateExpiry(false)
            ->setValidateCertificatePurpose(false)
            ->setValidateHostname(false);
    }

    /**
     * Configure for production environment (strict validation)
     */
    public function forProduction(): self
    {
        return $this->setAllowSelfSignedCertificates(false)
            ->setRequireTrustedCertificates(true)
            ->setValidateCertificateExpiry(true)
            ->setValidateCertificatePurpose(true)
            ->setValidateHostname(true);
    }

    /**
     * Configure to use custom CA for certificate verification
     */
    public function withCustomCa(?string $caPath = null, ?string $caFile = null): self
    {
        if ($caPath !== null) {
            $this->setCustomCaPath($caPath);
        }
        if ($caFile !== null) {
            $this->setCustomCaFile($caFile);
        }

        // When using custom CA, typically we want strict validation
        return $this->setRequireTrustedCertificates(true)
            ->setAllowSelfSignedCertificates(false);
    }

    /**
     * Configure to skip all certificate validation (use with caution!)
     */
    public function withoutCertificateValidation(): self
    {
        return $this->setRequireTrustedCertificates(false)
            ->setAllowSelfSignedCertificates(true)
            ->setValidateCertificateExpiry(false)
            ->setValidateCertificatePurpose(false)
            ->setValidateHostname(false);
    }

    /**
     * Configure to validate certificates but allow self-signed
     * (useful for internal networks with self-signed certs)
     */
    public function withSelfSignedValidation(): self
    {
        return $this->setAllowSelfSignedCertificates(true)
            ->setRequireTrustedCertificates(false)
            ->setValidateCertificateExpiry(true)
            ->setValidateCertificatePurpose(true)
            ->setValidateHostname(true);
    }

    /**
     * Configure mutual TLS (server requests client certificate)
     * Automatically enables client certificate request when custom CA is provided
     */
    public function withMutualTLS(?string $caPath = null, ?string $caFile = null): self
    {
        $this->withCustomCa($caPath, $caFile);

        // Auto-enable client certificate request when CA is configured
        if ($caPath !== null || $caFile !== null) {
            $this->setRequestClientCertificate(true);
        }

        return $this;
    }

    /**
     * Configure session resumption with storage backend
     */
    public function withSessionResumption(SessionStorage $storage, int $lifetimeSeconds = 86400): self
    {
        return $this->setEnableSessionResumption(true)
            ->setSessionStorage($storage)
            ->setSessionLifetime($lifetimeSeconds);
    }

    /**
     * Disable session resumption
     */
    public function withoutSessionResumption(): self
    {
        return $this->setEnableSessionResumption(false)
            ->setSessionStorage(null);
    }

    /**
     * Configure to support PSK-only mode (no (EC)DHE)
     */
    public function withPskOnlyMode(): self
    {
        return $this->setPskKeyExchangeModes([PskKeyExchangeModesExtension::PSK_KE]);
    }

    /**
     * Configure to support both PSK modes (with and without DHE)
     */
    public function withBothPskModes(): self
    {
        return $this->setPskKeyExchangeModes([
            PskKeyExchangeModesExtension::PSK_KE,
            PskKeyExchangeModesExtension::PSK_DHE_KE,
        ]);
    }

    /**
     * Configure external PSKs
     */
    public function withExternalPsks(array $externalPsks): self
    {
        $this->externalPsks = $externalPsks;

        return $this;
    }

    public function withSessionTicketSerializer(SessionTicketSerializer $serializer): self
    {
        $this->sessionTicketSerializer = $serializer;

        return $this;
    }

    public function getSessionTicketSerializer(): SessionTicketSerializer
    {
        return $this->sessionTicketSerializer ?? new PlainSessionTicketSerializer();
    }

    public function createPskResolver(): PskResolver
    {
        return new PskResolver(
            $this,
            $this->getSessionTicketSerializer(),
        );
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
            new SupportedVersionsExtensionProvider($this->supportedVersions),
            new SupportedGroupsExtensionProvider($this->supportedGroups),
            new KeyShareExtensionProvider($this->supportedGroups),
            new SignatureAlgorithmsExtensionProvider($this->signatureAlgorithms),
        ]);

        // Add PSK key exchange modes if session resumption is enabled
        if ($this->enableSessionResumption) {
            $this->clientHelloExtensions->add(
                new PskKeyExchangeModesExtensionProvider($this->pskKeyExchangeModes),
            );
        }

        if (null !== $this->serverName) {
            $this->addServerName($this->serverName);
        }
        if (!empty($this->supportedProtocols)) {
            $this->addAlpn($this->supportedProtocols);
        }

        // Add EarlyData extension if enabled (must come before PSK)
        if ($this->enableEarlyData) {
            $this->clientHelloExtensions->add(
                new EarlyDataExtensionProvider(),
            );
        }

        // Add PSK extension provider LAST (will be skipped if no PSKs available)
        // This MUST be the last extension per RFC 8446
        if ($this->enableSessionResumption) {
            $this->clientHelloExtensions->add(new PreSharedKeyExtensionProvider());
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
            new SupportedVersionsExtensionProvider($this->supportedVersions),
            new KeyShareExtensionProvider($this->supportedGroups),
        ]);

        if ($this->enableSessionResumption) {
            $this->serverHelloExtensions->add(new PreSharedKeyExtensionProvider());
        }
    }

    public function addServerEncryptedExtensions(): void
    {
        // Server EncryptedExtensionsMessage - Add extensions for server name acknowledgement (empty server name) and ALPN
        $this->encryptedExtensions->add(new ServerNameExtensionProvider());
        $this->encryptedExtensions->add(new AlpnExtensionProvider($this->supportedProtocols));

        // Add EarlyData extension provider (will include extension only if server accepted early data)
        // The provider checks context.isEarlyDataAccepted() to decide whether to include the extension
        if ($this->enableSessionResumption && $this->maxEarlyDataSize > 0) {
            $this->encryptedExtensions->add(new EarlyDataExtensionProvider($this->maxEarlyDataSize));
        }
    }
}
