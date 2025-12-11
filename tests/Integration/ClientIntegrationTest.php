<?php

namespace Php\TlsCraft\Tests\Integration;

use Php\TlsCraft\Client;
use Php\TlsCraft\Config;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\CraftException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * PHPUnit-based integration tests for TLS Client
 * Uses proper test framework with data providers for parameterized tests
 */
class ClientIntegrationTest extends TestCase
{
    private TestRunner $runner;

    protected function setUp(): void
    {
        $this->runner = new TestRunner();
    }

    protected function tearDown(): void
    {
        $this->runner->cleanup();
        TestCertificateGenerator::cleanupAll();
    }

    public static function tearDownAfterClass(): void
    {
        TestCertificateGenerator::cleanupAll();
    }

    /**
     * Data provider for different certificate algorithms
     * Returns [generatorFactory, configFactory] for each test case
     */
    public static function certificateAlgorithmProvider(): array
    {
        return [
            /* Once RSA-PSS salt length is supported, uncomment this test case */
            /*
            'RSA-2048' => [
                fn () => TestCertificateGenerator::forRSA(2048),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-256'],
                    signatureAlgorithms: ['rsa_pkcs1_sha256'],
                ),
            ],
            */
            'ECC-P256' => [
                fn () => TestCertificateGenerator::forECC('prime256v1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-256'],
                    signatureAlgorithms: ['ecdsa_secp256r1_sha256'],
                ),
            ],
            'ECC-P384' => [
                fn () => TestCertificateGenerator::forECC('secp384r1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-384'],
                    signatureAlgorithms: ['ecdsa_secp384r1_sha384'],
                ),
            ],
            'ECC-P521' => [
                fn () => TestCertificateGenerator::forECC('secp521r1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-521'],
                    signatureAlgorithms: ['ecdsa_secp521r1_sha512'],
                ),
            ],
        ];
    }

    /**
     * Test TLS client handshake with different certificate algorithms
     */
    #[Test]
    #[DataProvider('certificateAlgorithmProvider')]
    public function testClientHandshakeWithAlgorithm(callable $generatorFactory, callable $configFactory): void
    {
        /** @var TestCertificateGenerator $generator */
        $generator = $generatorFactory();
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $serverCode = $this->createServerCode($serverCerts);
        $serverAddress = $this->runner->startServerProcess($serverCode);

        // Parse address for Client constructor
        [$hostname, $port] = explode(':', $serverAddress);

        // Create config with algorithm-specific parameters
        $config = $configFactory();
        $config->forTesting(); // Enable self-signed cert acceptance

        $client = new Client($hostname, (int) $port, $config);

        // Main test code - debuggable with PHPUnit!
        $session = $client->connect(10.0);
        $this->assertNotNull($session, 'Client should establish session successfully');

        $testMessage = 'Hello World from PHPUnit Test';
        $session->send($testMessage);
        $response = $session->receive();

        $this->assertEquals("Echo: {$testMessage}", $response, 'Should receive echoed message');

        $session->close();

        $this->assertTrue(
            $this->runner->waitForCompletion(TestRunner::ROLE_SERVER, 15),
            'Server should complete successfully',
        );
    }

    /**
     * Test client with invalid certificate (when verification enabled)
     */
    #[Test]
    public function testClientWithInvalidCertificate(): void
    {
        $generator = TestCertificateGenerator::forRSA();
        $serverCerts = $generator->generateServerCertificateFiles('invalid-hostname.test');

        $serverCode = $this->createServerCode($serverCerts);
        $serverAddress = $this->runner->startServerProcess($serverCode);
        [$hostname, $port] = explode(':', $serverAddress);

        // Create config with certificate verification enabled
        $config = new Config(
            supportedVersions: ['TLS 1.3'],
            cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
        );

        // Enable certificate verification (should fail due to hostname mismatch)
        $config->setRequireTrustedCertificates(true)
            ->setAllowSelfSignedCertificates(false);

        $client = new Client($hostname, (int) $port, $config);

        $this->expectException(CraftException::class);
        $client->connect(5.0);
    }

    /**
     * Test multiple cipher suites negotiation
     */
    #[Test]
    public function testCipherSuiteNegotiation(): void
    {
        $generator = TestCertificateGenerator::forECC('prime256v1');
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $serverCode = $this->createServerCode($serverCerts);
        $serverAddress = $this->runner->startServerProcess($serverCode);
        [$hostname, $port] = explode(':', $serverAddress);

        $config = new Config(
            supportedVersions: ['TLS 1.3'],
            cipherSuites: [
                CipherSuite::TLS_AES_256_GCM_SHA384->value, // Prefer this
                CipherSuite::TLS_AES_128_GCM_SHA256->value, // Fallback
            ],
        );
        $config->forTesting();

        $client = new Client($hostname, (int) $port, $config);
        $session = $client->connect();

        // Verify negotiated cipher suite
        $context = $session->getContext();
        $negotiatedCipher = $context->getNegotiatedCipherSuite();

        $this->assertContains(
            $negotiatedCipher,
            [CipherSuite::TLS_AES_256_GCM_SHA384, CipherSuite::TLS_AES_128_GCM_SHA256],
            'Should negotiate one of the supported cipher suites',
        );

        $session->close();
    }

    /**
     * Test ALPN protocol negotiation
     */
    #[Test]
    public function testALPNNegotiation(): void
    {
        $generator = TestCertificateGenerator::forRSA();
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        // Use the existing combined cert file path
        $certFile = $serverCerts['combined_file'];

        // Server that supports specific ALPN protocols
        $serverCode = '
            $context = stream_context_create([
                "ssl" => [
                    "local_cert" => "' . $certFile . '",
                    "verify_peer" => false,
                    "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
                    "alpn_protocols" => "http/1.1,h2", // Server supports these
                ]
            ]);

            $server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
            if (!$server) {
                die("Failed to create server: $errstr ($errno)");
            }

            $address = stream_socket_get_name($server, false);

            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->notifyServerReady($address);

            $client = stream_socket_accept($server, 30);
            if ($client && stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER)) {
                $data = fread($client, 1024);
                fwrite($client, "ALPN-Echo: " . $data);
                fclose($client);
            }
            fclose($server);
        ';

        $serverAddress = $this->runner->startServerProcess($serverCode);
        [$hostname, $port] = explode(':', $serverAddress);

        $config = new Config(
            supportedVersions: ['TLS 1.3'],
            supportedProtocols: ['h2', 'http/1.1'], // Client preference order
        );
        $config->forTesting();

        $client = new Client($hostname, (int) $port, $config);
        $session = $client->connect();

        // Test that ALPN was negotiated
        $context = $session->getContext();
        $negotiatedProtocol = $context->getSelectedProtocol();
        $this->assertContains($negotiatedProtocol, ['h2', 'http/1.1'], 'Should negotiate ALPN protocol');

        $session->send('ALPN test');
        $response = $session->receive();
        $this->assertStringContainsString('ALPN-Echo:', $response);

        $session->close();
    }

    /**
     * Create server code for stream socket server
     */
    private function createServerCode(array $serverCerts): string
    {
        // Use the existing combined cert file path
        $certFile = $serverCerts['cert_file'];
        $keyFile = $serverCerts['key_file'];

        return '
            $context = stream_context_create([
                "ssl" => [
                    "local_cert" => "' . $certFile . '",
                    "local_pk" => "' . $keyFile . '",
                    "verify_peer" => false,
                    "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
                ]
            ]);

            $server = stream_socket_server("tlsv1.3://127.0.0.1:0", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
            if (!$server) {
                die("Failed to create server: $errstr ($errno)");
                while ($error = openssl_error_string()) {
                    echo $error . "\n";
                }
            }

            $address = stream_socket_get_name($server, false);
            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->notifyServerReady($address);

            $client = stream_socket_accept($server, 30);
            if (!$client) {
                fclose($server);
                die("Failed to accept client connection");
            }

            $data = fread($client, 1024);
            if ($data !== false) {
                fwrite($client, "Echo: " . $data);
            }

            fclose($client);
            fclose($server);
        ';
    }
}
