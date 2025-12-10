<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Crypto\Certificate as X509Certificate;
use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Logger;

class CertificateParser extends AbstractMessageParser
{
    public function parse(string $data): CertificateMessage
    {
        $payload = $this->parseHandshake($data, HandshakeType::CERTIFICATE);

        $offset = 0;

        // Certificate request context
        $contextLength = ord($payload[$offset]);
        ++$offset;
        $context = substr($payload, $offset, $contextLength);
        $offset += $contextLength;

        Logger::debug('Parsing Certificate message', [
            'Context length' => $contextLength,
            'Payload length' => strlen($payload),
        ]);

        // Certificate list
        $listLength = unpack('N', "\x00".substr($payload, $offset, 3))[1];
        $offset += 3;

        $x509Certificates = [];
        $endOffset = $offset + $listLength;

        Logger::debug('Certificate list', [
            'List length' => $listLength,
            'End offset' => $endOffset,
        ]);

        while ($offset < $endOffset) {
            $certLength = unpack('N', "\x00" . substr($payload, $offset, 3))[1];
            $offset += 3;

            $certDER = substr($payload, $offset, $certLength);
            $offset += $certLength;

            $extLength = unpack('n', substr($payload, $offset, 2))[1];
            $offset += 2;
            $extBytes = substr($payload, $offset, $extLength);
            $offset += $extLength;

            Logger::debug('Certificate entry parsed', [
                'DER length' => $certLength,
                'Extensions length' => $extLength,
            ]);

            // Convert DER to PEM for X509Certificate
            $pemData = "-----BEGIN CERTIFICATE-----\n";
            $pemData .= chunk_split(base64_encode($certDER), 64, "\n");
            $pemData .= "-----END CERTIFICATE-----\n";

            try {
                $x509Certificates[] = X509Certificate::fromPEM($pemData);
            } catch (\Exception $e) {
                throw new CraftException('Failed to parse certificate: ' . $e->getMessage());
            }
        }

        if (empty($x509Certificates)) {
            throw new CraftException('Certificate message contains no certificates');
        }

        Logger::debug('Certificate chain parsed', [
            'Certificate count' => count($x509Certificates),
        ]);

        $certificateChain = CertificateChain::fromCertificates($x509Certificates);

        return new CertificateMessage($context, $certificateChain);
    }
}
