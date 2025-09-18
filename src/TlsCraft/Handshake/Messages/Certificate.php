<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class Certificate extends Message
{
    public function __construct(
        public readonly string $certificateRequestContext,
        public readonly array $certificateList, // array of certificate entries
    ) {
        parent::__construct(HandshakeType::CERTIFICATE);
    }

    public function encode(): string
    {
        $encoded = chr(strlen($this->certificateRequestContext)).$this->certificateRequestContext;

        $certListData = '';
        foreach ($this->certificateList as $cert) {
            $certListData .= substr(pack('N', strlen($cert)), 1).$cert; // 3-byte length + cert
            $certListData .= "\x00\x00"; // Empty extensions
        }

        $encoded .= substr(pack('N', strlen($certListData)), 1).$certListData;

        return $encoded;
    }

    public static function decode(string $data): static
    {
        $offset = 0;

        // Certificate request context
        $contextLength = ord($data[$offset]);
        ++$offset;
        $context = substr($data, $offset, $contextLength);
        $offset += $contextLength;

        // Certificate list
        $listLength = unpack('N', "\x00".substr($data, $offset, 3))[1];
        $offset += 3;

        $certificates = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $certLength = unpack('N', "\x00".substr($data, $offset, 3))[1];
            $offset += 3;

            $certificate = substr($data, $offset, $certLength);
            $offset += $certLength;

            // Skip extensions
            $extLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2 + $extLength;

            $certificates[] = $certificate;
        }

        return new self($context, $certificates);
    }
}
