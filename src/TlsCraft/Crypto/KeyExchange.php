<?php

namespace Php\TlsCraft\Crypto;

interface KeyExchange
{
    public function generateKeyPair(): KeyPair;
}