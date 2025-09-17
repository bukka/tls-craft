<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Crypto\KeyShare;
use Php\TlsCraft\Crypto\NamedGroup;
use Php\TlsCraft\Messages\ExtensionType;

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
        return pack('n', strlen($keySharesData)) . $keySharesData;
    }

    public static function decode(string $data): static
    {
        $listLength = unpack('n', substr($data, 0, 2))[1];
        $offset = 2;

        $keyShares = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $keyShares[] = KeyShare::decode($data, $offset);
        }

        return new self($keyShares);
    }
}