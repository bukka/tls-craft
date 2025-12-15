<?php

namespace Php\TlsCraft\Tests\Integration;

use Exception;
use RuntimeException;

use const DEBUG_BACKTRACE_IGNORE_ARGS;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

/**
 * Certificate generator for integration tests
 * Generates CA, server, and client certificates for testing TLS implementations
 */
class TestCertificateGenerator
{
    public const KEY_TYPE_RSA = 'rsa';
    public const KEY_TYPE_EC = 'ec';

    private string $keyType;
    private array $keyOptions;
    private string $testName;

    private $ca;
    private $caKey;
    private $lastCert;
    private $lastKey;

    private static array $generatedFiles = [];

    private function __construct(string $keyType, array $keyOptions, string $testName)
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('OpenSSL extension required for certificate generation');
        }

        $this->keyType = $keyType;
        $this->keyOptions = $keyOptions;
        $this->testName = $testName;
        $this->generateCA();
    }

    /**
     * Create generator for RSA certificates
     */
    public static function forRSA(int $keySize = 2048, ?string $testName = null): self
    {
        $testName = $testName ?: self::getCallerName();

        return new self(self::KEY_TYPE_RSA, ['key_size' => $keySize], $testName);
    }

    /**
     * Create generator for ECC certificates
     */
    public static function forECC(string $curve = 'prime256v1', ?string $testName = null): self
    {
        $testName = $testName ?: self::getCallerName();

        return new self(self::KEY_TYPE_EC, ['curve' => $curve], $testName);
    }

    /**
     * Generate server certificate and save to files
     *
     * @return array{cert: string, key: string, cert_file: string, key_file: string, combined_file: string, ca_file: string, hostname: string}
     */
    public function generateServerCertificateFiles(string $hostname = 'localhost'): array
    {
        $this->lastKey = $this->generateKey();

        $dn = [
            'countryName' => 'US',
            'stateOrProvinceName' => 'Test State',
            'localityName' => 'Test City',
            'organizationName' => 'Test Server',
            'commonName' => $hostname,
        ];

        // Create temporary config file for SAN extension
        $sanConfig = $this->createServerCertConfig($hostname);
        $configFile = $this->getTempPath('server_openssl.cnf');
        file_put_contents($configFile, $sanConfig);
        self::$generatedFiles[] = $configFile;

        $config = [
            'config' => $configFile,
            'req_extensions' => 'v3_req',
            'x509_extensions' => 'usr_cert',
            'digest_alg' => 'sha256',
        ];

        try {
            $csr = openssl_csr_new($dn, $this->lastKey, $config);
            $this->lastCert = openssl_csr_sign($csr, $this->ca, $this->caKey, 30, $config);

            if (!$this->lastCert) {
                throw new RuntimeException('Failed to generate server certificate');
            }

            // Export certificate and key to PEM strings
            $certPem = '';
            $keyPem = '';
            $caCertPem = '';
            openssl_x509_export($this->lastCert, $certPem);
            openssl_pkey_export($this->lastKey, $keyPem);
            openssl_x509_export($this->ca, $caCertPem);

            // Generate file paths and write files
            $certFile = $this->getTempPath('server_cert.pem');
            $keyFile = $this->getTempPath('server_key.pem');
            $combinedFile = $this->getTempPath('server_combined.pem');
            $caFile = $this->getTempPath('ca.pem');

            // Include CA cert in chain for PHP's OpenSSL wrapper
            file_put_contents($certFile, $certPem.$caCertPem);
            file_put_contents($keyFile, $keyPem);
            file_put_contents($combinedFile, $certPem.$caCertPem.$keyPem);
            file_put_contents($caFile, $caCertPem);

            // Track generated files for cleanup
            self::$generatedFiles = array_merge(self::$generatedFiles, [$certFile, $keyFile, $combinedFile, $caFile]);

            return [
                'cert' => $certPem,
                'key' => $keyPem,
                'cert_file' => $certFile,
                'key_file' => $keyFile,
                'combined_file' => $combinedFile,
                'ca_file' => $caFile,
                'hostname' => $hostname,
            ];
        } catch (Exception $e) {
            throw new RuntimeException('Certificate generation failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Generate client certificate and save to files
     *
     * @return array{cert: string, key: string, cert_file: string, key_file: string, combined_file: string, ca_file: string, commonName: string}
     */
    public function generateClientCertificateFiles(string $commonName = 'client'): array
    {
        $this->lastKey = $this->generateKey();

        $dn = [
            'countryName' => 'US',
            'stateOrProvinceName' => 'Test State',
            'localityName' => 'Test City',
            'organizationName' => 'Test Client',
            'commonName' => $commonName,
        ];

        // Create temporary config file for client certificate
        $clientConfig = $this->createClientCertConfig();
        $configFile = $this->getTempPath('client_openssl.cnf');
        file_put_contents($configFile, $clientConfig);
        self::$generatedFiles[] = $configFile;

        $config = [
            'config' => $configFile,
            'req_extensions' => 'v3_req',
            'x509_extensions' => 'usr_cert',
            'digest_alg' => 'sha256',
        ];

        try {
            $csr = openssl_csr_new($dn, $this->lastKey, $config);
            $this->lastCert = openssl_csr_sign($csr, $this->ca, $this->caKey, 30, $config);

            if (!$this->lastCert) {
                throw new RuntimeException('Failed to generate client certificate');
            }

            // Export certificate and key to PEM strings
            $certPem = '';
            $keyPem = '';
            $caCertPem = '';
            openssl_x509_export($this->lastCert, $certPem);
            openssl_pkey_export($this->lastKey, $keyPem);
            openssl_x509_export($this->ca, $caCertPem);

            // Generate file paths and write files
            $certFile = $this->getTempPath('client_cert.pem');
            $keyFile = $this->getTempPath('client_key.pem');
            $combinedFile = $this->getTempPath('client_combined.pem');
            $caFile = $this->getTempPath('ca.pem');

            // Include CA cert in chain
            file_put_contents($certFile, $certPem.$caCertPem);
            file_put_contents($keyFile, $keyPem);
            file_put_contents($combinedFile, $certPem.$caCertPem.$keyPem);
            file_put_contents($caFile, $caCertPem);

            // Track generated files for cleanup
            self::$generatedFiles = array_merge(self::$generatedFiles, [$certFile, $keyFile, $combinedFile, $caFile]);

            return [
                'cert' => $certPem,
                'key' => $keyPem,
                'cert_file' => $certFile,
                'key_file' => $keyFile,
                'combined_file' => $combinedFile,
                'ca_file' => $caFile,
                'commonName' => $commonName,
            ];
        } catch (Exception $e) {
            throw new RuntimeException('Client certificate generation failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Get CA certificate PEM
     */
    public function getCACertificate(): string
    {
        $caCert = '';
        openssl_x509_export($this->ca, $caCert);

        return $caCert;
    }

    /**
     * Save CA certificate to file and return path
     */
    public function getCACertificateFile(): string
    {
        $caFile = $this->getTempPath('ca.pem');

        // Check if already exists to avoid duplicates
        if (!in_array($caFile, self::$generatedFiles)) {
            file_put_contents($caFile, $this->getCACertificate());
            self::$generatedFiles[] = $caFile;
        }

        return $caFile;
    }

    /**
     * Clean up all generated files
     */
    public static function cleanupAll(): void
    {
        foreach (self::$generatedFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }
        self::$generatedFiles = [];

        // Also clean up any remaining files matching our pattern
        $pattern = sys_get_temp_dir().'/tlscraft_test_*';
        foreach (glob($pattern) as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
    }

    /**
     * Generate CA certificate and key
     */
    private function generateCA(): void
    {
        $this->caKey = $this->generateKey();

        $dn = [
            'countryName' => 'US',
            'stateOrProvinceName' => 'Test State',
            'localityName' => 'Test City',
            'organizationName' => 'Test CA',
            'commonName' => 'Test CA Certificate',
        ];

        $config = $this->getOpenSSLConfig();
        $csr = openssl_csr_new($dn, $this->caKey, $config);
        $this->ca = openssl_csr_sign($csr, null, $this->caKey, 365, $config);

        if (!$this->ca) {
            throw new RuntimeException('Failed to generate CA certificate');
        }
    }

    private function generateKey()
    {
        return match ($this->keyType) {
            self::KEY_TYPE_RSA => $this->generateRSAKey(),
            self::KEY_TYPE_EC => $this->generateECKey(),
            default => throw new RuntimeException("Unsupported key type: {$this->keyType}"),
        };
    }

    private function generateRSAKey()
    {
        $keySize = $this->keyOptions['key_size'] ?? 2048;

        $key = openssl_pkey_new([
            'private_key_bits' => $keySize,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if (!$key) {
            throw new RuntimeException('Failed to generate RSA key');
        }

        return $key;
    }

    private function generateECKey()
    {
        $curve = $this->keyOptions['curve'] ?? 'prime256v1';

        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ]);

        if (!$key) {
            throw new RuntimeException("Failed to generate EC key for curve: $curve");
        }

        return $key;
    }

    private function getOpenSSLConfig(): array
    {
        // Use key-type specific defaults
        if ($this->keyType === self::KEY_TYPE_EC) {
            return [
                'digest_alg' => 'sha256',
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ];
        }

        return [
            'digest_alg' => 'sha256',
            'private_key_bits' => $this->keyOptions['key_size'] ?? 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
    }

    private function createServerCertConfig(string $hostname): string
    {
        return <<<CONFIG
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = {$hostname}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
CONFIG;
    }

    private function createClientCertConfig(): string
    {
        return <<<CONFIG
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
CONFIG;
    }

    private function getTempPath(string $suffix): string
    {
        $prefix = 'tlscraft_test_'.preg_replace('/[^a-zA-Z0-9_-]/', '_', $this->testName).'_';

        return sys_get_temp_dir().'/'.$prefix.$suffix;
    }

    private static function getCallerName(): string
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);

        // Look for the calling test method
        for ($i = 1; $i < count($trace); ++$i) {
            if (isset($trace[$i]['function']) && str_starts_with($trace[$i]['function'], 'test')) {
                return $trace[$i]['function'];
            }
        }

        // Fallback to class::method or just method name
        if (isset($trace[2]['class'], $trace[2]['function'])) {
            return $trace[2]['class'].'::'.$trace[2]['function'];
        }

        if (isset($trace[2]['function'])) {
            return $trace[2]['function'];
        }

        return 'unknown_test_'.uniqid();
    }
}
