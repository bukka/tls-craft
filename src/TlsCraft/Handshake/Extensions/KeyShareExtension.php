<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Crypto\KeyShare;
use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Key Share Extension
 */
class KeyShareExtension extends Extension
{
    /** @var KeyShare[] */
    private array $keyShares;

    public function __construct(array $keyShares)
    {
        $this->keyShares = $keyShares;
        parent::__construct(ExtensionType::KEY_SHARE);
    }

    /** @return KeyShare[] */
    public function getKeyShares(): array
    {
        return $this->keyShares;
    }

    public function getKeyShareForGroup(NamedGroup $group): ?KeyShare
    {
        foreach ($this->keyShares as $keyShare) {
            if ($keyShare->getGroup() === $group) {
                return $keyShare;
            }
        }

        return null;
    }

    public function encode(): string
    {
        $keySharesData = '';
        foreach ($this->keyShares as $keyShare) {
            $keySharesData .= $keyShare->encode();
        }

        return pack('n', strlen($keySharesData)).$keySharesData;
    }
}
