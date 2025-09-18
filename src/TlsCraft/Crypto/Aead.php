<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

use const OPENSSL_RAW_DATA;

class Aead
{
    private string $key;
    private string $iv;
    private string $algorithm;

    public function __construct(string $key, string $iv, CipherSuite $cipherSuite)
    {
        $this->key = $key;
        $this->iv = $iv;
        $this->algorithm = $cipherSuite->getAEADAlgorithm();
    }

    public function encrypt(string $plaintext, string $additionalData, int $sequenceNumber): string
    {
        $nonce = $this->constructNonce($sequenceNumber);

        $encrypted = openssl_encrypt(
            $plaintext,
            $this->algorithm,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $additionalData,
        );

        if ($encrypted === false) {
            throw new CryptoException('AEAD encryption failed');
        }

        return $encrypted.$tag;
    }

    public function decrypt(string $ciphertext, string $additionalData, int $sequenceNumber): string
    {
        $nonce = $this->constructNonce($sequenceNumber);

        // Extract tag (last 16 bytes for GCM)
        $tagLength = 16; // GCM tag length
        if (strlen($ciphertext) < $tagLength) {
            throw new CryptoException('Ciphertext too short');
        }

        $tag = substr($ciphertext, -$tagLength);
        $encrypted = substr($ciphertext, 0, -$tagLength);

        $decrypted = openssl_decrypt(
            $encrypted,
            $this->algorithm,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $additionalData,
        );

        if ($decrypted === false) {
            throw new CryptoException('AEAD decryption failed');
        }

        return $decrypted;
    }

    private function constructNonce(int $sequenceNumber): string
    {
        $seqBytes = pack('J', $sequenceNumber); // 64-bit big-endian

        // XOR the last 8 bytes of IV with sequence number
        $nonce = $this->iv;
        for ($i = 0; $i < 8; ++$i) {
            $nonce[strlen($this->iv) - 8 + $i] = chr(
                ord($this->iv[strlen($this->iv) - 8 + $i]) ^ ord($seqBytes[$i]),
            );
        }

        return $nonce;
    }
}
