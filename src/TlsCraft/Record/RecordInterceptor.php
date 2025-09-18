<?php

namespace Php\TlsCraft\Record;

interface RecordInterceptor
{
    public function beforeSend(Record $record): Record;

    public function afterReceive(Record $record): Record;

    public function shouldDrop(Record $record): bool;

    public function getDelay(Record $record): float;

    public function shouldFragment(Record $record): ?int;
}
