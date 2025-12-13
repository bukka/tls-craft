<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Logger;

class KeyDerivation
{
    public function hkdfExtract(string $salt, string $ikm, string $algorithm = 'sha256'): string
    {
        if ($salt === '') {
            $salt = str_repeat("\x00", strlen(hash($algorithm, '', true)));
        }

        $prk = hash_hmac($algorithm, $ikm, $salt, true);

        Logger::debug('HKDF-Extract', [
            'Algorithm' => $algorithm,
            'Salt' => $salt,   // auto-hex by Logger
            'IKM' => $ikm,
            'PRK' => $prk,
        ]);

        return $prk;
    }

    public function hkdfExpand(string $prk, string $info, int $length, string $algorithm = 'sha256'): string
    {
        $hashLength = strlen(hash($algorithm, '', true));
        $n = (int) ceil($length / $hashLength);
        if ($n > 255) {
            throw new CryptoException('HKDF expand length too large');
        }

        $okm = '';
        $t = '';
        for ($i = 1; $i <= $n; ++$i) {
            $t = hash_hmac($algorithm, $t.$info.chr($i), $prk, true);
            $okm .= $t;
        }
        $okm = substr($okm, 0, $length);

        Logger::debug('HKDF-Expand', [
            'Algorithm' => $algorithm,
            'PRK' => $prk,
            'Info' => $info,
            'Output length' => $length,
            'OKM' => $okm,
        ]);

        return $okm;
    }

    public function hkdf(string $ikm, string $salt, string $info, int $length, string $algorithm = 'sha256'): string
    {
        $prk = $this->hkdfExtract($salt, $ikm, $algorithm);

        return $this->hkdfExpand($prk, $info, $length, $algorithm);
    }

    public function deriveSecret(string $secret, string $label, string $messages, CipherSuite $cipherSuite): string
    {
        $hashAlg = $cipherSuite->getHashAlgorithm();
        $hashLength = $cipherSuite->getHashLength();

        $transcript = hash($hashAlg, $messages, true);
        $hkdfLabel = $this->buildHkdfLabel($hashLength, 'tls13 '.$label, $transcript);

        $derived = $this->hkdfExpand($secret, $hkdfLabel, $hashLength, $hashAlg);

        Logger::debug('Derive-Secret', [
            'Label' => 'tls13 '.$label,
            'Hash' => $hashAlg,
            'Transcript hash' => $transcript,
            'Result' => $derived,
        ]);

        return $derived;
    }

    public function expandLabel(
        string $secret,
        string $label,
        string $context,
        int $length,
        CipherSuite $cipherSuite,
    ): string {
        $hashAlg = $cipherSuite->getHashAlgorithm();
        $hkdfLabel = self::buildHkdfLabel($length, 'tls13 '.$label, $context);
        $expanded = $this->hkdfExpand($secret, $hkdfLabel, $length, $hashAlg);

        Logger::debug('Expand-Label', [
            'Label' => 'tls13 '.$label,
            'Context' => $context,
            'Length' => $length,
            'Algorithm' => $hashAlg,
            'Output' => $expanded,
        ]);

        return $expanded;
    }

    private function buildHkdfLabel(int $length, string $label, string $context): string
    {
        $hkdfLabel = pack('n', $length).chr(strlen($label)).$label.chr(strlen($context)).$context;

        Logger::debug('HKDF-Label', [
            'Length' => $length,
            'Label' => $label,
            'Context' => $context,
            'Encoded' => $hkdfLabel,
        ]);

        return $hkdfLabel;
    }
}
