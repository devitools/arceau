# Arceau Firewall

## How to install

`composer require devitools/arceau`

## Get started

Create a PHP file as below

```php
<?php

use Devitools\Arceau\Security\Firewall;

use const Devitools\Arceau\Security\Helper\FIREWALL_ALLOW;
use const Devitools\Arceau\Security\Helper\FIREWALL_DENY;

/**
 */
return static function () {
    $allowed = [
        'query:code=10&t=*',
        '172.30.0.1',
        '192.168.*',
    ];

    Firewall::instance()
        ->setDefaultMode(FIREWALL_DENY)
        ->addItem('10.0.0.*', FIREWALL_ALLOW)
        ->addItems($allowed, FIREWALL_ALLOW)
        ->handle();
};
```

Then use it anywhere

```php
$firewall = require __DIR__ . '/../../firewall.php';
$firewall();
```
