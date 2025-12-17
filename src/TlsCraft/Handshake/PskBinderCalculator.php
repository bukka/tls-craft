<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Crypto\PreSharedKey;
use Php\TlsCraft\Logger;

/**
 * PSK Binder Calculator
 *
 * Handles the complex logic of calculating PSK binders for ClientHello.
 * Binders must be calculated over the ClientHello transcript INCLUDING
 * all extensions but EXCLUDING the binders themselves.
 */
class PskBinderCalculator
{
    public function __construct(
        private readonly KeySchedule $keySchedule,
    ) {
    }

    /**
     * Calculate binders for all offered PSKs
     *
     * @param PreSharedKey[] $psks               Array of PSKs being offered
     * @param string         $partialClientHello Serialized ClientHello WITHOUT binder values
     * @param string         $previousTranscript Any previous transcript data (empty for first flight)
     *
     * @return string[] Array of binder values (one per PSK)
     */
    public function calculateBinders(
        array $psks,
        string $partialClientHello,
        string $previousTranscript = '',
    ): array {
        $binders = [];

        foreach ($psks as $index => $psk) {
            $binder = $this->calculateBinderForPsk(
                $psk,
                $partialClientHello,
                $previousTranscript,
            );

            $binders[] = $binder;

            Logger::debug("Calculated binder for PSK #{$index}", [
                'identity' => $psk->identity,
                'binder' => bin2hex($binder),
            ]);
        }

        return $binders;
    }

    /**
     * Calculate binder for a single PSK
     */
    private function calculateBinderForPsk(
        PreSharedKey $psk,
        string $partialClientHello,
        string $previousTranscript,
    ): string {
        // 1. Derive early secret from PSK
        $this->keySchedule->deriveEarlySecretWithPsk($psk->secret);

        // 2. Derive binder key
        // Use "res binder" for resumption PSK, "ext binder" for external PSK
        $isExternal = $this->isExternalPsk($psk);
        $binderKey = $this->keySchedule->derivePskBinderKey($isExternal);

        // 3. Derive finished key from binder key
        $finishedKey = $this->keySchedule->deriveFinishedKeyForBinder($binderKey);

        // 4. Calculate binder = HMAC(finished_key, Transcript-Hash(messages))
        $transcriptData = $previousTranscript.$partialClientHello;
        $binder = $this->keySchedule->calculatePskBinder($finishedKey, $transcriptData);

        return $binder;
    }

    /**
     * Determine if PSK is external (manually configured) or resumption (from ticket)
     *
     * This is a simple heuristic - in practice you might want to track this explicitly
     */
    private function isExternalPsk(PreSharedKey $psk): bool
    {
        // If the identity looks like a ticket (long random bytes), it's resumption
        // If it's a readable string, it's likely external
        // This is a heuristic - you might want to add an explicit flag to PreSharedKey
        return strlen($psk->identity) < 32 || ctype_print($psk->identity);
    }
}
