<?php

/**
 * tests/Integration/ClientTest.php
 * Example of testing TLS client - client runs in main process (debuggable)
 */

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/TestRunner.php';

use Php\TlsCraft\Client;
use Php\TlsCraft\Config;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Crypto\CipherSuite;

class ClientTest
{
    private TestRunner $runner;

    public function setUp(): void
    {
        $this->runner = new TestRunner();
    }

    public function tearDown(): void
    {
        $this->runner->cleanup();
    }

    /**
     * Test client handshake - CLIENT RUNS IN MAIN PROCESS (debuggable)
     */
    public function testClientHandshake(): void
    {
        echo "Testing TLS client handshake...\n";

        // Define server code to run in subprocess
        $serverCode = '
            // This runs in subprocess - basic TLS server using stream wrapper
            $context = stream_context_create([
                "ssl" => [
                    "local_cert" => __DIR__ . "/../fixtures/server.pem",
                    "local_pk" => __DIR__ . "/../fixtures/server.key",
                    "verify_peer" => false,
                ]
            ]);

            $server = stream_socket_server("tls://127.0.0.1:0", $errno, $errstr, 
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
            
            if (!$server) {
                die("Failed to create server: $errstr");
            }

            // Notify main process that server is ready
            $address = stream_socket_get_name($server, false);
            $runner = new Php\TlsCraft\Tests\Integration\TestRunner(true);
            $runner->notifyServerReady($address);

            // Accept connection and handle it
            $client = stream_socket_accept($server, 30);
            if ($client) {
                $data = fread($client, 1024);
                fwrite($client, "Echo: " . $data);
                fclose($client);
            }
            fclose($server);
        ';

        // Start server subprocess and get address
        $serverAddress = $this->runner->startServerProcess($serverCode);
        echo "Server started at: $serverAddress\n";

        // CLIENT CODE RUNS IN MAIN PROCESS - you can set breakpoints here!
        try {
            $config = new Config();
            $config->setSupportedCipherSuites([CipherSuite::TLS_AES_128_GCM_SHA256]);
            $config->setVerifyPeer(false); // For testing with self-signed certs

            $client = new Client($config);

            // You can set breakpoints here for debugging!
            echo "Connecting to server...\n";
            $result = $client->connect($serverAddress);
            assert($result, "Client should connect successfully");

            echo "Connected! Sending test data...\n";
            $client->send("Hello World");

            echo "Receiving response...\n";
            $response = $client->receive();

            echo "Received: $response\n";
            assert($response === "Echo: Hello World", "Should receive echoed message");

            $client->close();
            echo "Client test completed successfully!\n";

        } catch (Exception $e) {
            echo "Client test failed: " . $e->getMessage() . "\n";
            throw $e;
        } finally {
            // Wait for server to complete and cleanup
            $this->runner->waitForCompletion(TestRunner::ROLE_SERVER);
        }
    }
}

// Run if executed directly
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    $test = new ClientTest();
    $test->setUp();

    try {
        $test->testClientHandshake();
        echo "All client tests passed!\n";
    } catch (Exception $e) {
        echo "Test failed: " . $e->getMessage() . "\n";
        exit(1);
    } finally {
        $test->tearDown();
    }
}