<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class Aead
{
    public static function encrypt(
        string      $key,
        string      $iv,
        string      $plaintext,
        string      $additionalData,
        CipherSuite $cipherSuite,
        int         $sequenceNumber
    ): string
    {
        $nonce = self::constructNonce($iv, $sequenceNumber);
        $algorithm = $cipherSuite->getAEADAlgorithm();

        $encrypted = openssl_encrypt(
            $plaintext,
            $algorithm,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $additionalData
        );

        if ($encrypted === false) {
            throw new CryptoException("Aead encryption failed");
        }

        return $encrypted . $tag;
    }

    public static function decrypt(
        string      $key,
        string      $iv,
        string      $ciphertext,
        string      $additionalData,
        CipherSuite $cipherSuite,
        int         $sequenceNumber
    ): string
    {
        $nonce = self::constructNonce($iv, $sequenceNumber);
        $algorithm = $cipherSuite->getAEADAlgorithm();

        // Extract tag (last 16 bytes for GCM)
        $tagLength = 16; // GCM tag length
        if (strlen($ciphertext) < $tagLength) {
            throw new CryptoException("Ciphertext too short");
        }

        $tag = substr($ciphertext, -$tagLength);
        $encrypted = substr($ciphertext, 0, -$tagLength);

        $decrypted = openssl_decrypt(
            $encrypted,
            $algorithm,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $additionalData
        );

        if ($decrypted === false) {
            throw new CryptoException("Aead decryption failed");
        }

        return $decrypted;
    }

    private static function constructNonce(string $iv, int $sequenceNumber): string
    {
        $seqBytes = pack('J', $sequenceNumber); // 64-bit big-endian

        // XOR the last 8 bytes of IV with sequence number
        $nonce = $iv;
        for ($i = 0; $i < 8; $i++) {
            $nonce[strlen($iv) - 8 + $i] = chr(
                ord($iv[strlen($iv) - 8 + $i]) ^ ord($seqBytes[$i])
            );
        }

        return $nonce;
    }
}