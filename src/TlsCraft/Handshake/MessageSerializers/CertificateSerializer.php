<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\Certificate;

class CertificateSerializer extends AbstractMessageSerializer
{
    public function serialize(Certificate $message): string
    {
        $data = chr(strlen($message->certificateRequestContext)).$message->certificateRequestContext;

        $certListData = '';
        foreach ($message->certificateList as $cert) {
            $certListData .= substr(pack('N', strlen($cert)), 1).$cert; // 3-byte length + cert
            $certListData .= "\x00\x00"; // Empty extensions
        }

        $data .= substr(pack('N', strlen($certListData)), 1).$certListData;

        return $data;
    }
}
