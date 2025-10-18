<?php

namespace Php\TlsCraft\Exceptions;

class OpenSslException extends CryptoException
{
    public function __construct(string $message = '', int $code = 0, ?\Throwable $previous = null)
    {
        $errors = [];
        while ($error = openssl_error_string()) {
            $errors[] = $error;
        }
        $message = "$message; " . implode('; ', $errors);
        parent::__construct($message, $code, $previous);
    }

}
