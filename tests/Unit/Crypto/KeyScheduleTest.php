<?php

namespace Php\TlsCraft\Tests\Unit\Crypto;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\KeyDerivation;
use Php\TlsCraft\Crypto\KeySchedule;
use PHPUnit\Framework\TestCase;

class KeyScheduleTest extends TestCase
{
    /**
     * RFC 8448 Section 3 - Simple 1-RTT Handshake
     * This test validates the entire key schedule derivation against known test vectors
     */
    public function testRfc8448Section3KeySchedule(): void
    {
        // Test vectors from RFC 8448 Section 3
        $ecdhSecret = hex2bin('8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');

        $expectedEarlySecret = hex2bin('33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a');
        $expectedHandshakeSecret = hex2bin('1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac');
        $expectedMasterSecret = hex2bin('18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919');

        // Initialize KeySchedule
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $ks = new KeySchedule($cipher, $kd);

        // Derive early secret (with no PSK)
        $ks->deriveEarlySecret(null);

        // Use reflection to access private properties for testing
        $reflection = new \ReflectionClass($ks);
        $earlySecretProp = $reflection->getProperty('earlySecret');
        $actualEarlySecret = $earlySecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedEarlySecret),
            bin2hex($actualEarlySecret),
            'Early secret must match RFC 8448'
        );

        // Derive handshake secret
        $ks->deriveHandshakeSecret($ecdhSecret);

        $handshakeSecretProp = $reflection->getProperty('handshakeSecret');
        $actualHandshakeSecret = $handshakeSecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedHandshakeSecret),
            bin2hex($actualHandshakeSecret),
            'Handshake secret must match RFC 8448'
        );

        // Derive master secret
        $ks->deriveMasterSecret();

        $masterSecretProp = $reflection->getProperty('masterSecret');
        $actualMasterSecret = $masterSecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedMasterSecret),
            bin2hex($actualMasterSecret),
            'Master secret must match RFC 8448'
        );
    }

    /**
     * RFC 8448 Section 3 - Traffic Secrets
     * Tests derivation of handshake traffic secrets from transcript
     */
    public function testRfc8448Section3TrafficSecrets(): void
    {
        // RFC 8448 §3 ECDH shared secret
        $ecdhSecret = hex2bin('8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');

        // Handshake bytes = Handshake(type,3-byte length,body) for CH then SH (no record headers, no CCS)
        $clientHello = hex2bin('010000c00303cb34ecb1e78163' .
            'ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283' .
            '024dece7000006130113031302010000910000000b' .
            '0009000006736572766572ff01000100000a001400' .
            '12001d001700180019010001010102010301040023' .
            '0000003300260024001d002099381de560e4bd43d2' .
            '3d8e435a7dbafeb3c06e51c13cae4d5413691e529a' .
            'af2c002b0003020304000d0020001e040305030603' .
            '020308040805080604010501060102010402050206' .
            '020202002d00020101001c00024001');
        $serverHello = hex2bin('020000560303a6af06a4121860' .
            'dc5e6e60249cd34c95930c8ac5cb1434dac155772e' .
            'd3e2692800130100002e00330024001d0020c98288' .
            '76112095fe66762bdbf7c672e156d6cc253b833df1' .
            'dd69b1b04e751f0f002b00020304');

        // Sanity-check transcript hash equals RFC value
        $transcript = hash('sha256', $clientHello . $serverHello, true);
        $this->assertSame(
            '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8',
            bin2hex($transcript),
            'Transcript hash (CH||SH) must match RFC 8448 §3'
        );

        $expectedServerHsTraffic = hex2bin('b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38');
        $expectedClientHsTraffic = hex2bin('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');

        // Initialize and derive secrets
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $ks = new KeySchedule($cipher, $kd);

        $ks->deriveEarlySecret(null);
        $ks->deriveHandshakeSecret($ecdhSecret);

        // Add handshake messages to transcript
        $ks->addHandshakeMessage($clientHello);
        $ks->addHandshakeMessage($serverHello);

        // Derive traffic secrets
        $actualServerHsTraffic = $ks->getServerHandshakeTrafficSecret();
        $actualClientHsTraffic = $ks->getClientHandshakeTrafficSecret();

        $this->assertSame(
            bin2hex($expectedServerHsTraffic),
            bin2hex($actualServerHsTraffic),
            'Server handshake traffic secret must match RFC 8448'
        );

        $this->assertSame(
            bin2hex($expectedClientHsTraffic),
            bin2hex($actualClientHsTraffic),
            'Client handshake traffic secret must match RFC 8448'
        );
    }

    /**
     * Test that handshake secret derivation is deterministic
     */
    public function testHandshakeSecretIsDeterministic(): void
    {
        $ecdhSecret = random_bytes(32);

        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();

        // First derivation
        $ks1 = new KeySchedule($cipher, $kd);
        $ks1->deriveEarlySecret(null);
        $ks1->deriveHandshakeSecret($ecdhSecret);

        $reflection = new \ReflectionClass($ks1);
        $prop = $reflection->getProperty('handshakeSecret');
        $secret1 = $prop->getValue($ks1);

        // Second derivation with same inputs
        $ks2 = new KeySchedule($cipher, $kd);
        $ks2->deriveEarlySecret(null);
        $ks2->deriveHandshakeSecret($ecdhSecret);

        $secret2 = $prop->getValue($ks2);

        $this->assertSame(
            bin2hex($secret1),
            bin2hex($secret2),
            'Handshake secret must be deterministic for same inputs'
        );
    }

    /**
     * Test that different ECDH secrets produce different handshake secrets
     */
    public function testDifferentEcdhProducesDifferentHandshakeSecret(): void
    {
        $ecdhSecret1 = random_bytes(32);
        $ecdhSecret2 = random_bytes(32);

        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();

        $ks1 = new KeySchedule($cipher, $kd);
        $ks1->deriveEarlySecret(null);
        $ks1->deriveHandshakeSecret($ecdhSecret1);

        $ks2 = new KeySchedule($cipher, $kd);
        $ks2->deriveEarlySecret(null);
        $ks2->deriveHandshakeSecret($ecdhSecret2);

        $reflection = new \ReflectionClass($ks1);
        $prop = $reflection->getProperty('handshakeSecret');

        $secret1 = $prop->getValue($ks1);
        $secret2 = $prop->getValue($ks2);

        $this->assertNotSame(
            bin2hex($secret1),
            bin2hex($secret2),
            'Different ECDH secrets must produce different handshake secrets'
        );
    }

    /**
     * Test application keys derivation
     */
    public function testApplicationKeysDerivation(): void
    {
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $ks = new KeySchedule($cipher, $kd);

        // Use a known traffic secret
        $trafficSecret = hex2bin('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');

        $keys = $ks->deriveApplicationKeys($trafficSecret);

        $this->assertIsArray($keys);
        $this->assertArrayHasKey('key', $keys);
        $this->assertArrayHasKey('iv', $keys);
        $this->assertSame($cipher->getKeyLength(), strlen($keys['key']));
        $this->assertSame($cipher->getIVLength(), strlen($keys['iv']));
    }

    /**
     * Test finished key derivation
     */
    public function testFinishedKeyDerivation(): void
    {
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $ks = new KeySchedule($cipher, $kd);

        $trafficSecret = hex2bin('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');

        $finishedKey = $ks->getFinishedKey($trafficSecret);

        $this->assertSame($cipher->getHashLength(), strlen($finishedKey));
    }
}
