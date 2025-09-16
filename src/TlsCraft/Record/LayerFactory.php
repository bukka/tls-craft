<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Context;
use Php\TlsCraft\Control\FlowController;

class LayerFactory
{
    public function createEncryptedLayer(Connection $connection, Context $context, ?FlowController $flowController = null): EncryptedLayer
    {
        $baseLayer = new Layer($connection, $flowController);
        return new EncryptedLayer($baseLayer, $context);
    }
}