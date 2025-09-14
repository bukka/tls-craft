<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class KeyDerivation
{
    public static function hkdfExtract(string $salt, string $ikm, string $algorithm = 'sha256'): string
    {
        if (empty($salt)) {
            $salt = str_repeat("\x00", hash_hmac_algos() ? hash('sha256', '', true) : 32);
        }

        return hash_hmac($algorithm, $ikm, $salt, true);
    }

    public static function hkdfExpand(string $prk, string $info, int $length, string $algorithm = 'sha256'): string
    {
        $hashLength = strlen(hash($algorithm, '', true));
        $n = (int)ceil($length / $hashLength);

        if ($n > 255) {
            throw new CryptoException("HKDF expand length too large");
        }

        $okm = '';
        $t = '';

        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac($algorithm, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }

    public static function hkdf(string $ikm, string $salt, string $info, int $length, string $algorithm = 'sha256'): string
    {
        $prk = self::hkdfExtract($salt, $ikm, $algorithm);
        return self::hkdfExpand($prk, $info, $length, $algorithm);
    }

    public static function deriveSecret(string $secret, string $label, string $messages, CipherSuite $cipherSuite): string
    {
        $hashAlg = $cipherSuite->getHashAlgorithm();
        $hashLength = $cipherSuite->getHashLength();

        $transcript = hash($hashAlg, $messages, true);
        $hkdfLabel = self::buildHkdfLabel($hashLength, "tls13 " . $label, $transcript);

        return self::hkdfExpand($secret, $hkdfLabel, $hashLength, $hashAlg);
    }

    public static function expandLabel(string $secret, string $label, string $context, int $length, CipherSuite $cipherSuite): string
    {
        $hashAlg = $cipherSuite->getHashAlgorithm();
        $hkdfLabel = self::buildHkdfLabel($length, "tls13 " . $label, $context);

        return self::hkdfExpand($secret, $hkdfLabel, $length, $hashAlg);
    }

    private static function buildHkdfLabel(int $length, string $label, string $context): string
    {
        $hkdfLabel = pack('n', $length); // Length (2 bytes)
        $hkdfLabel .= chr(strlen($label)) . $label; // Label
        $hkdfLabel .= chr(strlen($context)) . $context; // Context

        return $hkdfLabel;
    }
}