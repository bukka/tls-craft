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
     * Calculate binders for all offered PSKs (client-side)
     *
     * @param PreSharedKey[] $psks               Array of PSKs being offered
     * @param string         $partialClientHello Serialized ClientHello WITH handshake header, WITHOUT binders
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
                'cipher_suite' => $psk->cipherSuite->name,
                'is_external' => !$psk->isResumption(),
                'binder_length' => strlen($binder),
                'binder' => bin2hex($binder),
            ]);
        }

        return $binders;
    }

    /**
     * Calculate and verify a single binder (server-side)
     *
     * @param PreSharedKey $psk                The PSK to verify
     * @param string       $partialClientHello Serialized ClientHello WITH handshake header, WITHOUT binders
     * @param bool         $isExternal         True for external PSK, false for resumption PSK
     * @param string       $previousTranscript Any previous transcript data (empty for initial ClientHello)
     *
     * @return string The calculated binder value
     */
    public function calculateBinder(
        PreSharedKey $psk,
        string $partialClientHello,
        bool $isExternal,
        string $previousTranscript = '',
    ): string {
        $binder = $this->calculateBinderForPsk(
            $psk,
            $partialClientHello,
            $previousTranscript,
            $isExternal,
        );

        Logger::debug('Calculated single binder for verification', [
            'cipher_suite' => $psk->cipherSuite->name,
            'is_external' => $isExternal,
            'binder_length' => strlen($binder),
            'binder' => bin2hex($binder),
        ]);

        return $binder;
    }

    /**
     * Calculate binder for a single PSK (internal method)
     */
    private function calculateBinderForPsk(
        PreSharedKey $psk,
        string $partialClientHello,
        string $previousTranscript,
        ?bool $isExternal = null,
    ): string {
        // Determine if external PSK (if not explicitly provided)
        if ($isExternal === null) {
            $isExternal = !$psk->isResumption();
        }

        // Create temporary key schedule for this PSK's cipher suite
        $keySchedule = $this->context->getCryptoFactory()->createKeySchedule(
            $psk->cipherSuite,
            $this->context->getHandshakeTranscript(),
        );

        // 1. Derive early secret from PSK
        $keySchedule->deriveEarlySecretWithPsk($psk->secret);

        // 2. Derive binder key
        // Use "ext binder" for external PSKs, "res binder" for resumption PSKs
        $binderKey = $keySchedule->derivePskBinderKey($isExternal);

        // 3. Derive finished key from binder key
        $finishedKey = $keySchedule->deriveFinishedKeyForBinder($binderKey);

        // 4. Calculate binder = HMAC(finished_key, Transcript-Hash(messages))
        $transcriptData = $previousTranscript.$partialClientHello;
        $binder = $keySchedule->calculatePskBinder($finishedKey, $transcriptData);

        Logger::debug('Binder calculation details', [
            'cipher_suite' => $psk->cipherSuite->name,
            'is_external' => $isExternal,
            'label' => $isExternal ? 'ext binder' : 'res binder',
            'partial_ch_length' => strlen($partialClientHello),
            'previous_transcript_length' => strlen($previousTranscript),
            'total_transcript_length' => strlen($transcriptData),
        ]);

        return $binder;
    }
}
