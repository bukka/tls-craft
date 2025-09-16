<?php

namespace Php\TlsCraft;

use Closure;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Extensions\ClientHelloExtensionProviders;
use Php\TlsCraft\Extensions\EncryptedExtensionsProviders;
use Php\TlsCraft\Extensions\ServerHelloExtensionProviders;
use Php\TlsCraft\Messages\Providers\SupportedVersionsProvider;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\State\ProtocolValidator;

class Config
{
    public array $cipherSuites;
    public array $supportedGroups;
    public array $signatureAlgorithms;

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
        // Add supported_versions extension by default
        $this->clientHelloExtensions->add(
            new SupportedVersionsProvider([Version::TLS_1_3])
        );
    }
}