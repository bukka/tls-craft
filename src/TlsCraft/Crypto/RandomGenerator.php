<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class RandomGenerator
{
    public function generate(int $length): string
    {
        if ($length <= 0) {
            throw new CryptoException('Invalid random length');
        }

        $random = random_bytes($length);
        if (strlen($random) !== $length) {
            throw new CryptoException('Failed to generate random bytes');
        }

        return $random;
    }

    public function generateClientRandom(): string
    {
        return $this->generate(32);
    }

    public function generateServerRandom(): string
    {
        return $this->generate(32);
    }
}
