<?php

namespace Php\TlsCraft\Tests\Integration;

use Php\TlsCraft\Config;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * PHPUnit-based integration tests for TLS Server
 * Uses TlsCraft Server with OpenSSL stream_socket_client as test client
 */
class ServerIntegrationTest extends TestCase
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
            // RSA-PSS requires salt length control (PHP 8.6+ after PR merge)
            // 'RSA-2048' => [
            //     fn () => TestCertificateGenerator::forRSA(2048),
            //     fn () => new Config(
            //         supportedVersions: ['TLS 1.3'],
            //         cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
            //         supportedGroups: ['P-256'],
            //         signatureAlgorithms: ['rsa_pss_rsae_sha256'],
            //     ),
            // ],
            'ECC-P256' => [
                fn () => TestCertificateGenerator::forECC('prime256v1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                ),
            ],
            'ECC-P384' => [
                fn () => TestCertificateGenerator::forECC('secp384r1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                ),
            ],
            'ECC-P521' => [
                fn () => TestCertificateGenerator::forECC('secp521r1'),
                fn () => new Config(
                    supportedVersions: ['TLS 1.3'],
                    cipherSuites: [CipherSuite::TLS_AES_128_GCM_SHA256->value],
                ),
            ],
        ];
    }

    /**
     * Test TLS server handshake with different certificate algorithms
     */
    #[Test]
    #[DataProvider('certificateAlgorithmProvider')]
    public function testServerHandshakeWithAlgorithm(callable $generatorFactory, callable $configFactory): void
    {
        $generator = $generatorFactory();
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        // Create config with algorithm-specific parameters
        /** @var Config $config */
        $config = $configFactory();
        $config->withCertificate($serverCerts['cert_file'], $serverCerts['key_file']);

        // Create TlsCraft server in main process
        $server = new Server($config);

        $server->listen('127.0.0.1', 0);
        $serverAddress = $server->getAddress();

        // Start OpenSSL client in subprocess - it will wait for server to notify
        $clientCode = $this->createClientCode();
        $this->runner->startClientProcess($clientCode, $serverAddress);

        // Notify client that server is ready
        $this->runner->notifyClientReady();

        // Accept connection and handle in main process
        $session = $server->accept(30.0);
        $testMessage = $session->receive(5);

        $this->assertEquals('Hello', $testMessage, 'Server should receive test message');

        $session->send('Echo: '.$testMessage);
        $session->close();
        $server->close();

        // Wait for client to complete
        $this->assertTrue(
            $this->runner->waitForCompletion(TestRunner::ROLE_CLIENT, 15),
            'Client should complete successfully',
        );
    }

    /**
     * Test server with multiple cipher suites
     */
    #[Test]
    public function testServerCipherSuiteNegotiation(): void
    {
        $generator = TestCertificateGenerator::forECC('prime256v1');
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $config = new Config(
            supportedVersions: ['TLS 1.3'],
            cipherSuites: [
                CipherSuite::TLS_AES_256_GCM_SHA384->value,
                CipherSuite::TLS_AES_128_GCM_SHA256->value,
            ],
        );
        $config->withCertificate($serverCerts['cert_file'], $serverCerts['key_file']);

        // Create server in main process
        $server = new Server($config);

        $server->listen('127.0.0.1', 0);
        $serverAddress = $server->getAddress();

        // Start client subprocess
        $clientCode = $this->createClientCode('cipher-test');
        $this->runner->startClientProcess($clientCode, $serverAddress);
        $this->runner->notifyClientReady();

        // Handle connection
        $session = $server->accept(30.0);
        $testMessage = $session->receive(11); // 'cipher-test' length

        $this->assertEquals('cipher-test', $testMessage);

        $session->send('Echo: '.$testMessage);
        $session->close();
        $server->close();

        $this->assertTrue(
            $this->runner->waitForCompletion(TestRunner::ROLE_CLIENT, 15),
            'Client should complete successfully',
        );
    }

    /**
     * Test server ALPN negotiation
     */
    #[Test]
    public function testServerALPNNegotiation(): void
    {
        $generator = TestCertificateGenerator::forECC('prime256v1');
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $config = new Config(
            supportedVersions: ['TLS 1.3'],
            supportedProtocols: ['h2', 'http/1.1'],
        );
        $config->withCertificate($serverCerts['cert_file'], $serverCerts['key_file']);

        // Create server in main process
        $server = new Server($config);

        $server->listen('127.0.0.1', 0);
        $serverAddress = $server->getAddress();

        // Start client with ALPN
        $clientCode = $this->createClientCode('alpn-test', alpn: 'h2,http/1.1');
        $this->runner->startClientProcess($clientCode, $serverAddress);
        $this->runner->notifyClientReady();

        // Handle connection
        $session = $server->accept(30.0);
        $testMessage = $session->receive(9); // 'alpn-test' length

        $this->assertEquals('alpn-test', $testMessage);

        $session->send('Echo: '.$testMessage);
        $session->close();
        $server->close();

        $this->assertTrue(
            $this->runner->waitForCompletion(TestRunner::ROLE_CLIENT, 15),
            'Client should complete successfully',
        );
    }

    /**
     * Test server handles client disconnect gracefully
     */
    #[Test]
    public function testServerClientDisconnect(): void
    {
        $generator = TestCertificateGenerator::forECC('prime256v1');
        $serverCerts = $generator->generateServerCertificateFiles('localhost');

        $config = new Config();
        $config->withCertificate($serverCerts['cert_file'], $serverCerts['key_file']);

        // Create server in main process
        $server = new Server($config);

        $server->listen('127.0.0.1', 0);
        $serverAddress = $server->getAddress();

        // Start client that will disconnect immediately after handshake
        $clientCode = $this->createClientCode('', disconnectImmediately: true);
        $this->runner->startClientProcess($clientCode, $serverAddress);
        $this->runner->notifyClientReady();

        // Try to accept and handle disconnect
        try {
            $session = $server->accept(30.0);
            // Client disconnected, so receive should fail or return empty
            $testMessage = $session->receive(5);
            $session->close();
        } catch (CraftException $e) {
            // Expected - client disconnected
        }

        $server->close();

        $this->assertTrue(
            $this->runner->waitForCompletion(TestRunner::ROLE_CLIENT, 15),
            'Client should complete successfully',
        );
    }

    /**
     * Create OpenSSL stream client code for subprocess
     * Client waits for server to notify it's ready before connecting
     */
    private function createClientCode(
        string $message = 'Hello',
        ?string $alpn = null,
        bool $disconnectImmediately = false,
    ): string {
        $alpnConfig = $alpn ? "'alpn_protocols' => '$alpn'," : '';

        $sendReceive = $disconnectImmediately ? '
            // Just disconnect immediately after handshake
            fclose($client);
        ' : '
            fwrite($client, "'.$message.'");
            $response = fread($client, 1024);

            if ($response !== "Echo: '.$message.'") {
                fclose($client);
                die("Unexpected response: $response");
            }

            fclose($client);
        ';

        return '
            // Wait for server to notify it is ready
            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->waitForServerNotification();

            $context = stream_context_create([
                "ssl" => [
                    "verify_peer" => false,
                    "verify_peer_name" => false,
                    "allow_self_signed" => true,
                    "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
                    '.$alpnConfig.'
                ]
            ]);

            $client = @stream_socket_client(
                "tls://{{ADDR}}",
                $errno,
                $errstr,
                10,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if ($client === false) {
                $errors = [];
                while ($error = openssl_error_string()) {
                    $errors[] = $error;
                }
                die("Failed to connect: $errstr ($errno). OpenSSL errors: " . implode(", ", $errors));
            }

            '.$sendReceive.'
        ';
    }
}
