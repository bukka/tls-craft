<?php

namespace Php\TlsCraft\Tests\Unit\Crypto;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\KeyDerivation;
use PHPUnit\Framework\TestCase;

class KeyDerivationTest extends TestCase
{
    /** RFC 5869 — Test Case 1 (SHA-256): hkdfExtract */
    public function testHkdfExtractMatchesRfc5869Case1(): void
    {
        $ikm  = hex2bin(str_repeat('0b', 22));                 // 22 bytes of 0x0b
        $salt = hex2bin('000102030405060708090a0b0c');          // 13 bytes
        $expPrk = hex2bin('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');

        $kd = new KeyDerivation();
        $prk = $kd->hkdfExtract($salt, $ikm, 'sha256');

        $this->assertSame(bin2hex($expPrk), bin2hex($prk), 'PRK must match RFC 5869 TC1');
    }

    /** RFC 5869 — Test Case 1 (SHA-256): hkdfExpand */
    public function testHkdfExpandMatchesRfc5869Case1(): void
    {
        $prk = hex2bin('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');                 // 10 bytes
        $length = 42;
        $expOkm = hex2bin('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

        $kd = new KeyDerivation();
        $okm = $kd->hkdfExpand($prk, $info, $length, 'sha256');

        $this->assertSame(bin2hex($expOkm), bin2hex($okm), 'OKM must match RFC 5869 TC1');
    }

    /** RFC 5869 — Test Case 1 (SHA-256): combined hkdf() */
    public function testHkdfCombinedMatchesRfc5869Case1(): void
    {
        $ikm  = hex2bin(str_repeat('0b', 22));
        $salt = hex2bin('000102030405060708090a0b0c');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $length = 42;
        $expOkm = hex2bin('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

        $kd = new KeyDerivation();
        $okm = $kd->hkdf($ikm, $salt, $info, $length, 'sha256');

        $this->assertSame(bin2hex($expOkm), bin2hex($okm), 'Combined HKDF must match RFC 5869 TC1');
    }

    /** hkdfExtract with empty salt should use zero-salt of hash length */
    public function testHkdfExtractWithEmptySaltUsesZeroSaltOfHashLen(): void
    {
        $ikm = random_bytes(32);
        $zeroSalt = str_repeat("\x00", strlen(hash('sha256', '', true)));
        $ref = hash_hmac('sha256', $ikm, $zeroSalt, true);

        $kd = new KeyDerivation();
        $prk = $kd->hkdfExtract('', $ikm, 'sha256');

        $this->assertSame(bin2hex($ref), bin2hex($prk), 'Empty salt must equal explicit zero-salt HMAC');
    }

    /**
     * TLS 1.3 HKDF-Expand-Label for KEY/IV using your SERVER_HANDSHAKE_TRAFFIC_SECRET
     * Ciphersuite: TLS_AES_128_GCM_SHA256
     * Secret (from keylog): a2c75c1a82878a863a628d8052e882475cfecb4b67763e585e8826556f949a76
     * Expected:
     *   key(16) = f9ca909c9db85dec8821c2f4dcd9c2d1
     *   iv(12)  = f29ea3bc801f3138ca81585e
     */
    public function testTls13ExpandLabelKeyAndIvFromServerHandshakeSecret(): void
    {
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $serverHsSecret = hex2bin('a2c75c1a82878a863a628d8052e882475cfecb4b67763e585e8826556f949a76');

        $kd = new KeyDerivation();
        $key = $kd->expandLabel($serverHsSecret, 'key', '', $cipher->getKeyLength(), $cipher);
        $iv  = $kd->expandLabel($serverHsSecret, 'iv',  '', $cipher->getIVLength(),  $cipher);

        $this->assertSame('f9ca909c9db85dec8821c2f4dcd9c2d1', bin2hex($key), 'TLS 1.3 AEAD key must match');
        $this->assertSame('f29ea3bc801f3138ca81585e',         bin2hex($iv),  'TLS 1.3 AEAD IV must match');
    }

    /** deriveSecret() should equal Expand-Label(secret, label, Hash(messages), HashLen) */
    public function testDeriveSecretMatchesExpandLabelWithTranscriptHash(): void
    {
        $cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
        $secret   = random_bytes($cipher->getHashLength()); // pretend this is some traffic secret
        $messages = random_bytes(100);                      // pretend transcript bytes
        $hashAlg  = $cipher->getHashAlgorithm();
        $ctxHash  = hash($hashAlg, $messages, true);

        $kd = new KeyDerivation();
        $viaDeriveSecret = $kd->deriveSecret($secret, 'test-label', $messages, $cipher);
        $viaExpandLabel  = $kd->expandLabel($secret, 'test-label', $ctxHash, $cipher->getHashLength(), $cipher);

        $this->assertSame(bin2hex($viaExpandLabel), bin2hex($viaDeriveSecret), 'deriveSecret must be equivalent to Expand-Label(..., Hash(messages))');
    }

    /** Sanity: lengths produced match enum-specified key/iv sizes for AES-128-GCM and AES-256-GCM */
    public function testKeyAndIvLengthsForCommonCipherSuites(): void
    {
        $kd = new KeyDerivation();

        // AES-128-GCM-SHA256
        $c128 = CipherSuite::TLS_AES_128_GCM_SHA256;
        $sec128 = random_bytes($c128->getHashLength());
        $k128 = $kd->expandLabel($sec128, 'key', '', $c128->getKeyLength(), $c128);
        $iv128 = $kd->expandLabel($sec128, 'iv', '', $c128->getIVLength(), $c128);
        $this->assertSame($c128->getKeyLength(), strlen($k128));
        $this->assertSame($c128->getIVLength(),  strlen($iv128));

        // AES-256-GCM-SHA384
        $c256 = CipherSuite::TLS_AES_256_GCM_SHA384;
        $sec256 = random_bytes($c256->getHashLength());
        $k256 = $kd->expandLabel($sec256, 'key', '', $c256->getKeyLength(), $c256);
        $iv256 = $kd->expandLabel($sec256, 'iv', '', $c256->getIVLength(), $c256);
        $this->assertSame($c256->getKeyLength(), strlen($k256));
        $this->assertSame($c256->getIVLength(),  strlen($iv256));
    }
}
