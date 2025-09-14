<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class RandomGenerator
{
    public static function generate(int $length): string
    {
        if ($length <= 0) {
            throw new CryptoException("Invalid random length");
        }

        $random = random_bytes($length);
        if (strlen($random) !== $length) {
            throw new CryptoException("Failed to generate random bytes");
        }

        return $random;
    }

    public static function generateClientRandom(): string
    {
        return self::generate(32);
    }

    public static function generateServerRandom(): string
    {
        return self::generate(32);
    }
}