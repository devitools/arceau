<?php

declare(strict_types=1);

namespace Devitools\Arceau\Cache;

/**
 * Interface Driver
 *
 * @package Devitools\Arceau\Cache
 */
interface Driver
{
    /**
     * @return string
     */
    public function name(): string;

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has(string $key): bool;

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function get(string $key);

    /**
     * @param string $key
     * @param mixed $value
     * @param int $ttl
     *
     * @return bool
     */
    public function set(string $key, $value, int $ttl = 60): bool;
}
