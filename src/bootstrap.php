<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security\Helper;

const FIREWALL_ALLOW = 'allow';
const FIREWALL_DENY = 'deny';

/**
 * @return string
 */
function ip(): string
{
    return $_SERVER['HTTP_CLIENT_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['HTTP_X_FORWARDED']
        ?? $_SERVER['HTTP_FORWARDED_FOR']
        ?? $_SERVER['HTTP_FORWARDED']
        ?? $_SERVER['REMOTE_ADDR'];
}

/**
 * @param ...$args
 */
function debug(...$args)
{
    echo '<pre>';
    /** @noinspection ForgottenDebugOutputInspection */
    var_dump($args);
    echo '</pre>';
}

/**
 * @param ...$args
 */
function stop(...$args)
{
    debug(...$args);
    exit();
}
