<?php

namespace Php\TlsCraft\Tests\Integration;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\CraftException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Php\TlsCraft\Client;
use Php\TlsCraft\Config;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Crypto\CipherSuite;

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
     */
    public static function certificateAlgorithmProvider(): array
    {
        return [
            'RSA-2048' => [
                'generator' => fn() => TestCertificateGenerator::forRSA(2048),
                'config_factory' => fn() => new Config(
                    supportedVersions: [Version::TLS_1_3],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-256'], // RSA can work with any group
                    signatureAlgorithms: [SignatureScheme::RSA_PKCS1_SHA256->value]
                )
            ],
            'ECC-P256' => [
                'generator' => fn() => TestCertificateGenerator::forECC('prime256v1'),
                'config_factory' => fn() => new Config(
                    supportedVersions: [Version::TLS_1_3],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-256'],
                    signatureAlgorithms: [SignatureScheme::ECDSA_SECP256R1_SHA256->value]
                )
            ],
            'ECC-P384' => [
                'generator' => fn() => TestCertificateGenerator::forECC('secp384r1'),
                'config_factory' => fn() => new Config(
                    supportedVersions: [Version::TLS_1_3],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-384'],
                    signatureAlgorithms: [SignatureScheme::ECDSA_SECP384R1_SHA384->value]
                )
            ],
            'ECC-P521' => [
                'generator' => fn() => TestCertificateGenerator::forECC('secp521r1'),
                'config_factory' => fn() => new Config(
                    supportedVersions: [Version::TLS_1_3],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                    supportedGroups: ['P-521'],
                    signatureAlgorithms: [SignatureScheme::ECDSA_SECP521R1_SHA512->value]
                )
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
        $generator = $generatorFactory();
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $serverCode = $this->createServerCode($serverCerts);
        $serverAddress = $this->runner->startServerProcess($serverCode);

        // Parse address for Client constructor
        [$hostname, $port] = explode(':', $serverAddress);

        // Create config with algorithm-specific parameters
        $config = $configFactory();
        $config->forTesting(); // Enable self-signed cert acceptance

        $client = new Client($hostname, (int)$port, $config);

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
            'Server should complete successfully'
        );
    }

    /**
     * Test client connection timeout handling
     */
    #[Test]
    public function testClientConnectionTimeout(): void
    {
        // Create a server that doesn't accept connections
        $serverCode = '
            $server = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            socket_bind($server, "127.0.0.1", 0);
            // Note: No socket_listen() - this will cause connection to be refused
            
            $address = "";
            $port = 0;
            socket_getsockname($server, $address, $port);
            
            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->notifyServerReady("$address:$port");
            
            // Keep socket open but don\'t listen
            sleep(5);
            socket_close($server);
        ';

        $serverAddress = $this->runner->startServerProcess($serverCode);
        [$hostname, $port] = explode(':', $serverAddress);

        $config = new Config();
        $config->forTesting();
        $client = new Client($hostname, (int)$port, $config);

        $this->expectException(CraftException::class);
        $client->connect(2.0); // Short timeout
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
            supportedVersions: [Version::TLS_1_3],
            cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value]
        );

        // Enable certificate verification (should fail due to hostname mismatch)
        $config->setRequireTrustedCertificates(true)
            ->setAllowSelfSignedCertificates(false);

        $client = new Client($hostname, (int)$port, $config);

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
            supportedVersions: [Version::TLS_1_3],
            cipherSuites: [
                CipherSuite::TLS_AES_256_GCM_SHA384->value, // Prefer this
                CipherSuite::TLS_AES_128_GCM_SHA256->value, // Fallback
            ]
        );
        $config->forTesting();

        $client = new Client($hostname, (int)$port, $config);
        $session = $client->connect();

        // Verify negotiated cipher suite
        $context = $session->getContext();
        $negotiatedCipher = $context->getNegotiatedCipherSuite();

        $this->assertContains(
            $negotiatedCipher,
            [CipherSuite::TLS_AES_256_GCM_SHA384, CipherSuite::TLS_AES_128_GCM_SHA256],
            'Should negotiate one of the supported cipher suites'
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

        // Server that supports specific ALPN protocols
        $serverCode = '
            $context = stream_context_create([
                "ssl" => [
                    "local_cert" => "' . $serverCerts['combined_file'] . '",
                    "verify_peer" => false,
                    "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
                    "alpn_protocols" => "http/1.1,h2", // Server supports these
                ]
            ]);

            $server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
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
            supportedVersions: [Version::TLS_1_3],
            supportedProtocols: ['h2', 'http/1.1'] // Client preference order
        );
        $config->forTesting();

        $client = new Client($hostname, (int)$port, $config);
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

    private function createServerCode(array $serverCerts): string
    {
        return '
            $context = stream_context_create([
                "ssl" => [
                    "local_cert" => "' . $serverCerts['combined_file'] . '",
                    "verify_peer" => false,
                    "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
                ]
            ]);

            $server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
            if (!$server) {
                die("Failed to create server: $errstr ($errno)");
            }

            $address = stream_socket_get_name($server, false);
            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->notifyServerReady($address);

            $client = stream_socket_accept($server, 30);
            if (!$client) {
                die("Failed to accept client connection");
            }

            if (!stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER)) {
                die("Failed to enable TLS on server side");
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