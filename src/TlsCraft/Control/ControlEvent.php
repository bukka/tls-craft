<?php

namespace Php\TlsCraft\Control;

class ControlEvent
{
    public function __construct(
        public readonly string $type,
        public readonly array $data = [],
    ) {
    }
}
