<?php

namespace Php\TlsCraft;

use Closure;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Extensions\ClientHelloExtensionProviders;
use Php\TlsCraft\Extensions\EncryptedExtensionsProviders;
use Php\TlsCraft\Extensions\ServerHelloExtensionProviders;
use Php\TlsCraft\Messages\Providers\AlpnExtensionProvider;
use Php\TlsCraft\Messages\Providers\KeyShareExtensionProvider;
use Php\TlsCraft\Messages\Providers\ServerNameExtensionProvider;
use Php\TlsCraft\Messages\Providers\SignatureAlgorithmsProvider;
use Php\TlsCraft\Messages\Providers\SupportedVersionsProvider;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\State\ProtocolValidator;

class Config
{
    public array $cipherSuites;
    public array $supportedGroups;
    public array $signatureAlgorithms;

    public ?string $serverName = null;

    public array $supportedProtocols = [];

    public ClientHelloExtensionProviders $clientHelloExtensions;
    public ServerHelloExtensionProviders $serverHelloExtensions;
    public EncryptedExtensionsProviders $encryptedExtensions;

    public ?Closure $onStateChange = null;
    public ?Closure $onKeyUpdate = null;
    public ?Closure $onAlert = null;

    public bool $allowProtocolViolations = false;
    public ?ProtocolValidator $customValidator = null;

    // Connection options
    public array $connectionOptions = [];
    public $requireTrustedCertificates = false;
    public $allowSelfSignedCertificates = true;

    public function __construct()
    {
        // Default cipher suites
        $this->cipherSuites = [
            CipherSuite::TLS_AES_128_GCM_SHA256->value,
            CipherSuite::TLS_AES_256_GCM_SHA384->value,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256->value,
        ];

        // Default supported groups
        $this->supportedGroups = ['P-256', 'P-384', 'P-521'];

        // Default signature algorithms
        $this->signatureAlgorithms = [
            SignatureScheme::RSA_PKCS1_SHA256->value,
            SignatureScheme::RSA_PKCS1_SHA384->value,
            SignatureScheme::ECDSA_SECP256R1_SHA256->value,
        ];

        // Initialize extension providers
        $this->clientHelloExtensions = new ClientHelloExtensionProviders();
        $this->serverHelloExtensions = new ServerHelloExtensionProviders();
        $this->encryptedExtensions = new EncryptedExtensionsProviders();

        // Add default extensions
        $this->addDefaultExtensions();
    }

    private function addDefaultExtensions(): void
    {
        $this->addRequiredClientExtensions();
        $this->addServerExtensions();
    }

    private function addRequiredClientExtensions(): void
    {
        // MANDATORY TLS 1.3 extensions
        $this->clientHelloExtensions->addMany([
            new SupportedVersionsProvider([Version::TLS_1_3]),
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
            new SupportedVersionsProvider([Version::TLS_1_3]),
            new KeyShareExtensionProvider($this->supportedGroups),
        ]);
    }

    public function addServerEncryptedExtensions(): void
    {
        // Server EncryptedExtensions - Add extensions for server name acknowledgement (empty server name) and ALPN
        $this->encryptedExtensions->add(new ServerNameExtensionProvider());
        $this->encryptedExtensions->add(new AlpnExtensionProvider($this->supportedProtocols));;
    }
}