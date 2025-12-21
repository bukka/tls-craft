<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Context;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\PreSharedKey;

/**
 * PSK Binder Calculator
 *
 * Calculates PSK binders for ClientHello based on the partial transcript
 * (ClientHello with zero binders).
 */
class PskBinderCalculator
{
    public function __construct(
        private readonly Context $context,
    ) {
    }

    /**
     * Calculate binders for all offered PSKs
     *
     * @param PreSharedKey[] $psks               Array of PSKs being offered
     * @param string         $partialClientHello Serialized ClientHello WITH zero binders
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
                'psk' => $psk->secret,
                'is_resumption' => $psk->isResumption(),
                'binder_length' => strlen($binder),
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
        // Create temporary key schedule for this PSK's cipher suite
        $keySchedule = $this->context->getCryptoFactory()->createKeySchedule(
            $psk->cipherSuite,
            $this->context->getHandshakeTranscript(),
        );

        // 1. Derive early secret from PSK
        $keySchedule->deriveEarlySecretWithPsk($psk->secret);

        // 2. Derive binder key
        // Use "res binder" for resumption PSKs, "ext binder" for external PSKs
        $isExternal = !$psk->isResumption();
        $binderKey = $keySchedule->derivePskBinderKey($isExternal);

        // 3. Derive finished key from binder key
        $finishedKey = $keySchedule->deriveFinishedKeyForBinder($binderKey);

        // 4. Calculate binder = HMAC(finished_key, Transcript-Hash(messages))
        $transcriptData = $previousTranscript.$partialClientHello;
        $binder = $keySchedule->calculatePskBinder($finishedKey, $transcriptData);

        return $binder;
    }
}
