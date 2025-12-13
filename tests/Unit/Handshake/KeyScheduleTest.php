<?php

namespace Php\TlsCraft\Tests\Unit\Handshake;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\KeyDerivation;
use Php\TlsCraft\Handshake\HandshakeTranscript;
use Php\TlsCraft\Handshake\KeySchedule;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

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

        // Initialize KeySchedule with transcript
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $transcript = new HandshakeTranscript();
        $ks = new KeySchedule($cipher, $kd, $transcript);

        // Derive early secret (with no PSK)
        $ks->deriveEarlySecret(null);

        // Use reflection to access private properties for testing
        $reflection = new ReflectionClass($ks);
        $earlySecretProp = $reflection->getProperty('earlySecret');
        $actualEarlySecret = $earlySecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedEarlySecret),
            bin2hex($actualEarlySecret),
            'Early secret must match RFC 8448',
        );

        // Derive handshake secret
        $ks->deriveHandshakeSecret($ecdhSecret);

        $handshakeSecretProp = $reflection->getProperty('handshakeSecret');
        $actualHandshakeSecret = $handshakeSecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedHandshakeSecret),
            bin2hex($actualHandshakeSecret),
            'Handshake secret must match RFC 8448',
        );

        // Derive master secret
        $ks->deriveMasterSecret();

        $masterSecretProp = $reflection->getProperty('masterSecret');
        $actualMasterSecret = $masterSecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedMasterSecret),
            bin2hex($actualMasterSecret),
            'Master secret must match RFC 8448',
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
        $clientHello = hex2bin('010000c00303cb34ecb1e78163'.
            'ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283'.
            '024dece7000006130113031302010000910000000b'.
            '0009000006736572766572ff01000100000a001400'.
            '12001d001700180019010001010102010301040023'.
            '0000003300260024001d002099381de560e4bd43d2'.
            '3d8e435a7dbafeb3c06e51c13cae4d5413691e529a'.
            'af2c002b0003020304000d0020001e040305030603'.
            '020308040805080604010501060102010402050206'.
            '020202002d00020101001c00024001');
        $serverHello = hex2bin('020000560303a6af06a4121860'.
            'dc5e6e60249cd34c95930c8ac5cb1434dac155772e'.
            'd3e2692800130100002e00330024001d0020c98288'.
            '76112095fe66762bdbf7c672e156d6cc253b833df1'.
            'dd69b1b04e751f0f002b00020304');

        // Sanity-check transcript hash equals RFC value
        $transcript = hash('sha256', $clientHello.$serverHello, true);
        $this->assertSame(
            '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8',
            bin2hex($transcript),
            'Transcript hash (CH||SH) must match RFC 8448 §3',
        );

        $expectedServerHsTraffic = hex2bin('b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38');
        $expectedClientHsTraffic = hex2bin('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');

        // Initialize with transcript
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $handshakeTranscript = new HandshakeTranscript();
        $ks = new KeySchedule($cipher, $kd, $handshakeTranscript);

        $ks->deriveEarlySecret(null);
        $ks->deriveHandshakeSecret($ecdhSecret);

        // Add handshake messages to transcript
        $handshakeTranscript->addMessage($clientHello);
        $handshakeTranscript->addMessage($serverHello);

        // Derive traffic secrets
        $actualServerHsTraffic = $ks->getServerHandshakeTrafficSecret();
        $actualClientHsTraffic = $ks->getClientHandshakeTrafficSecret();

        $this->assertSame(
            bin2hex($expectedServerHsTraffic),
            bin2hex($actualServerHsTraffic),
            'Server handshake traffic secret must match RFC 8448',
        );

        $this->assertSame(
            bin2hex($expectedClientHsTraffic),
            bin2hex($actualClientHsTraffic),
            'Client handshake traffic secret must match RFC 8448',
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
        $transcript1 = new HandshakeTranscript();
        $ks1 = new KeySchedule($cipher, $kd, $transcript1);
        $ks1->deriveEarlySecret(null);
        $ks1->deriveHandshakeSecret($ecdhSecret);

        $reflection = new ReflectionClass($ks1);
        $prop = $reflection->getProperty('handshakeSecret');
        $secret1 = $prop->getValue($ks1);

        // Second derivation with same inputs
        $transcript2 = new HandshakeTranscript();
        $ks2 = new KeySchedule($cipher, $kd, $transcript2);
        $ks2->deriveEarlySecret(null);
        $ks2->deriveHandshakeSecret($ecdhSecret);

        $secret2 = $prop->getValue($ks2);

        $this->assertSame(
            bin2hex($secret1),
            bin2hex($secret2),
            'Handshake secret must be deterministic for same inputs',
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

        $transcript1 = new HandshakeTranscript();
        $ks1 = new KeySchedule($cipher, $kd, $transcript1);
        $ks1->deriveEarlySecret(null);
        $ks1->deriveHandshakeSecret($ecdhSecret1);

        $transcript2 = new HandshakeTranscript();
        $ks2 = new KeySchedule($cipher, $kd, $transcript2);
        $ks2->deriveEarlySecret(null);
        $ks2->deriveHandshakeSecret($ecdhSecret2);

        $reflection = new ReflectionClass($ks1);
        $prop = $reflection->getProperty('handshakeSecret');

        $secret1 = $prop->getValue($ks1);
        $secret2 = $prop->getValue($ks2);

        $this->assertNotSame(
            bin2hex($secret1),
            bin2hex($secret2),
            'Different ECDH secrets must produce different handshake secrets',
        );
    }

    /**
     * Test application keys derivation
     */
    public function testApplicationKeysDerivation(): void
    {
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $transcript = new HandshakeTranscript();
        $ks = new KeySchedule($cipher, $kd, $transcript);

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
        $transcript = new HandshakeTranscript();
        $ks = new KeySchedule($cipher, $kd, $transcript);

        $trafficSecret = hex2bin('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');

        $finishedKey = $ks->getFinishedKey($trafficSecret);

        $this->assertSame($cipher->getHashLength(), strlen($finishedKey));
    }

    /**
     * RFC 8448 Section 3 - Application Traffic Secrets and Keys
     * Tests derivation of application traffic secrets and keys from complete transcript
     */
    public function testRfc8448Section3ApplicationTrafficSecrets(): void
    {
        // RFC 8448 §3 ECDH shared secret
        $ecdhSecret = hex2bin('8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');

        // All handshake messages (no record headers, no content-type padding)
        $clientHello = hex2bin('010000c00303cb34ecb1e78163'.
            'ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283'.
            '024dece7000006130113031302010000910000000b'.
            '0009000006736572766572ff01000100000a001400'.
            '12001d001700180019010001010102010301040023'.
            '0000003300260024001d002099381de560e4bd43d2'.
            '3d8e435a7dbafeb3c06e51c13cae4d5413691e529a'.
            'af2c002b0003020304000d0020001e040305030603'.
            '020308040805080604010501060102010402050206'.
            '020202002d00020101001c00024001');

        $serverHello = hex2bin('020000560303a6af06a4121860'.
            'dc5e6e60249cd34c95930c8ac5cb1434dac155772e'.
            'd3e2692800130100002e00330024001d0020c98288'.
            '76112095fe66762bdbf7c672e156d6cc253b833df1'.
            'dd69b1b04e751f0f002b00020304');

        $encryptedExtensions = hex2bin('080000240022000a001400'.
            '12001d00170018001901000101010201030104001c'.
            '0002400100000000');

        $certificate = hex2bin('0b0001b9000001b50001b03082'.
            '01ac30820115a003020102020102300d06092a8648'.
            '86f70d01010b0500300e310c300a06035504031303'.
            '727361301e170d3136303733303031323335395a17'.
            '0d3236303733303031323335395a300e310c300a06'.
            '03550403130372736130819f300d06092a864886f7'.
            '0d010101050003818d0030818902818100b4bb498f'.
            '8279303d980836399b36c6988c0c68de55e1bdb826'.
            'd3901a2461eafd2de49a91d015abbc9a95137ace6c'.
            '1af19eaa6af98c7ced43120998e187a80ee0ccb052'.
            '4b1b018c3e0b63264d449a6d38e22a5fda43084674'.
            '8030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193'.
            'eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203'.
            '010001a31a301830090603551d1304023000300b06'.
            '03551d0f0404030205a0300d06092a864886f70d01'.
            '010b05000381810085aad2a0e5b9276b908c65f73a'.
            '7267170618a54c5f8a7b337d2df7a594365417f2ea'.
            'e8f8a58c8f8172f9319cf36b7fd6c55b80f21a0301'.
            '5156726096fd335e5e67f2dbf102702e608ccae6be'.
            'c1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b'.
            '1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8'.
            '961229ac9187b42b4de10000');

        $certificateVerify = hex2bin('0f000084080400805a747c'.
            '5d88fa9bd2e55ab085a61015b7211f824cd484145a'.
            'b3ff52f1fda8477b0b7abc90db78e2d33a5c141a07'.
            '8653fa6bef780c5ea248eeaaa785c4f394cab6d30b'.
            'be8d4859ee511f602957b15411ac027671459e4644'.
            '5c9ea58c181e818e95b8c3fb0bf3278409d3be152a'.
            '3da5043e063dda65cdf5aea20d53dfacd42f74f3');

        $serverFinished = hex2bin('140000209b9b141d906337fbd2cb'.
            'dce71df4deda4ab42c309572cb7fffee5454b78f07'.
            '18');

        $clientFinished = hex2bin('14000020a8ec436d677634ae525a'.
            'c1fcebe11a039ec17694fac6e98527b642f2edd5ce'.
            '61');

        // Transcript hash for application secrets = Hash(CH||SH||EE||Cert||CV||SF||CF)
        $transcriptForAppSecrets = $clientHello.$serverHello.$encryptedExtensions.
            $certificate.$certificateVerify.$serverFinished.$clientFinished;
        $expectedTranscriptHash = hash('sha256', $transcriptForAppSecrets, true);

        // From RFC 8448 page 10
        $this->assertSame(
            '209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d',
            bin2hex($expectedTranscriptHash),
            'Application transcript hash must match RFC 8448',
        );

        // Expected values from RFC 8448
        $expectedMasterSecret = hex2bin('18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919');
        $expectedClientAppTraffic = hex2bin('9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5');
        $expectedServerAppTraffic = hex2bin('a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643');

        // Expected application keys for client write (from RFC 8448 page 13)
        $expectedClientWriteKey = hex2bin('17422dda596ed5d9acd890e3c63f5051');
        $expectedClientWriteIV = hex2bin('5b78923dee08579033e523d9');

        // Expected application keys for server write (from RFC 8448 page 10)
        $expectedServerWriteKey = hex2bin('9f02283b6c9c07efc26bb9f2ac92e356');
        $expectedServerWriteIV = hex2bin('cf782b88dd83549aadf1e984');

        // Initialize KeySchedule
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $kd = new KeyDerivation();
        $transcript = new HandshakeTranscript();
        $ks = new KeySchedule($cipher, $kd, $transcript);

        // Derive early and handshake secrets
        $ks->deriveEarlySecret(null);
        $ks->deriveHandshakeSecret($ecdhSecret);

        // Add all handshake messages to transcript (in order)
        $transcript->addMessage($clientHello);
        $transcript->addMessage($serverHello);
        $transcript->addMessage($encryptedExtensions);
        $transcript->addMessage($certificate);
        $transcript->addMessage($certificateVerify);
        $transcript->addMessage($serverFinished);
        $transcript->addMessage($clientFinished);

        // Derive master secret
        $ks->deriveMasterSecret();

        // Get master secret via reflection
        $reflection = new ReflectionClass($ks);
        $masterSecretProp = $reflection->getProperty('masterSecret');
        $actualMasterSecret = $masterSecretProp->getValue($ks);

        $this->assertSame(
            bin2hex($expectedMasterSecret),
            bin2hex($actualMasterSecret),
            'Master secret must match RFC 8448',
        );

        // Get application traffic secrets
        $actualClientAppTraffic = $ks->getClientApplicationTrafficSecret();
        $actualServerAppTraffic = $ks->getServerApplicationTrafficSecret();

        $this->assertSame(
            bin2hex($expectedClientAppTraffic),
            bin2hex($actualClientAppTraffic),
            'Client application traffic secret must match RFC 8448',
        );

        $this->assertSame(
            bin2hex($expectedServerAppTraffic),
            bin2hex($actualServerAppTraffic),
            'Server application traffic secret must match RFC 8448',
        );

        // Derive and verify application keys
        $clientKeys = $ks->deriveApplicationKeys($actualClientAppTraffic);
        $serverKeys = $ks->deriveApplicationKeys($actualServerAppTraffic);

        $this->assertSame(
            bin2hex($expectedClientWriteKey),
            bin2hex($clientKeys['key']),
            'Client write key must match RFC 8448',
        );

        $this->assertSame(
            bin2hex($expectedClientWriteIV),
            bin2hex($clientKeys['iv']),
            'Client write IV must match RFC 8448',
        );

        $this->assertSame(
            bin2hex($expectedServerWriteKey),
            bin2hex($serverKeys['key']),
            'Server write key must match RFC 8448',
        );

        $this->assertSame(
            bin2hex($expectedServerWriteIV),
            bin2hex($serverKeys['iv']),
            'Server write IV must match RFC 8448',
        );
    }
}
