<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Logger;
use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Exceptions\OpenSslException;
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
            throw new OpenSslException('AEAD encryption failed');
        }

        Logger::debug('AEAD Encrypt', [
            'Algorithm'        => $this->algorithm,
            'Seq'              => $sequenceNumber,
            'Key length'       => strlen($this->key),
            'Key'              => $this->key,
            'IV length'        => strlen($this->iv),
            'IV'               => $this->iv,
            'Nonce'            => $nonce,
            'AAD'              => $additionalData,
            'Plaintext length' => strlen($plaintext),
            'Ciphertext length'=> strlen($encrypted),
            'Tag'              => $tag,
        ]);

        return $encrypted.$tag;
    }

    public function decrypt(string $ciphertext, string $additionalData, int $sequenceNumber): string
    {
        $nonce = $this->constructNonce($sequenceNumber);

        Logger::debug('AEAD Decrypt (pre)', [
            'Algorithm'         => $this->algorithm,
            'Seq'               => $sequenceNumber,
            'Key length'        => strlen($this->key),
            'Key'               => $this->key,
            'IV length'         => strlen($this->iv),
            'IV'                => $this->iv,
            'Nonce'             => $nonce,
            'AAD'               => $additionalData,
            'Ciphertext length' => strlen($ciphertext),
            'Ciphertext'        => $ciphertext,
        ]);

        $tagLength = 16;
        if (strlen($ciphertext) < $tagLength) {
            throw new CryptoException('Ciphertext too short');
        }

        $tag = substr($ciphertext, -$tagLength);
        $encrypted = substr($ciphertext, 0, -$tagLength);

        Logger::debug('AEAD Decrypt (split)', [
            'Tag'                   => $tag,
            'Encrypted data length' => strlen($encrypted),
        ]);

        $decrypted = openssl_decrypt(
            $encrypted,
            $this->algorithm,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $additionalData
        );

        if ($decrypted === false) {
            Logger::error('AEAD decryption failed', [
                'Algorithm' => $this->algorithm,
                'Seq'       => $sequenceNumber,
                'Tag'       => $tag,
                'Nonce'     => $nonce,
                'AAD'       => $additionalData,
            ]);
            throw new OpenSslException('AEAD decryption failed');
        }

        return $decrypted;
    }

    private function constructNonce(int $sequenceNumber): string
    {
        $high = ($sequenceNumber >> 32) & 0xFFFFFFFF;
        $low  = $sequenceNumber & 0xFFFFFFFF;
        $seqBytes = pack('NN', $high, $low);

        $nonce = $this->iv;
        $ivLen = strlen($this->iv);
        for ($i = 0; $i < 8; $i++) {
            $nonce[$ivLen - 8 + $i] = chr(
                ord($this->iv[$ivLen - 8 + $i]) ^ ord($seqBytes[$i])
            );
        }

        Logger::debug('Nonce construction', [
            'Sequence'  => $sequenceNumber,
            'Seq bytes' => $seqBytes,
            'IV'        => $this->iv,
            'Final'     => $nonce,
        ]);

        return $nonce;
    }
}
