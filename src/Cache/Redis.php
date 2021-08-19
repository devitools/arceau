<?php /** @noinspection PhpComposerExtensionStubsInspection */

declare(strict_types=1);

namespace Devitools\Arceau\Cache;

use Redis as Connection;
use RuntimeException;

/**
 * Class Redis
 *
 * @package Devitools\Arceau\Cache
 */
trait Redis
{
    /**
     * @param string $host
     * @param string $port
     *
     * @return $this
     */
    public function configureRedis(string $host, string $port): self
    {
        if (isset($this->cacheDriver)) {
            throw new RuntimeException("The driver '{$this->cacheDriver->name()}' is already configured");
        }

        $this->cacheDriver = new class ($host, $port) implements Driver {
            /**
             * @var string
             */
            private $host;

            /**
             * @var string
             */
            private $port;

            /**
             * @var Connection
             */
            private $connection;

            /**
             *  Anonymous constructor.
             *
             * @param string $host
             * @param string $port
             */
            public function __construct(string $host, string $port)
            {
                $this->host = $host;
                $this->port = $port;
            }

            /**
             * @return Connection
             */
            protected function connection(): Connection
            {
                if (!$this->connection) {
                    $redis = new Connection();
                    $connected = $redis->connect($this->host, (int)$this->port, 1, NULL, 100);
                    if (!$connected) {
                        throw new RuntimeException('Error on redis connection');
                    }
                    $this->connection = $redis;
                }
                return $this->connection;
            }

            /**
             * @return string
             */
            public function name(): string
            {
                return 'redis';
            }

            /**
             * @param string $key
             *
             * @return bool
             */
            public function has(string $key): bool
            {
                return (bool)$this->connection()->exists($key);
            }

            /**
             * @param string $key
             *
             * @return mixed
             */
            public function get(string $key)
            {
                $value = $this->connection()->get($key);
                if ($value === 'true') {
                    return true;
                }
                if ($value === 'false') {
                    return false;
                }
                return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
            }

            /**
             * @param string $key
             * @param $value
             * @param int $ttl
             *
             * @return bool
             */
            public function set(string $key, $value, int $ttl = 60): bool
            {
                return $this->connection()->set($key, json_encode($value, JSON_THROW_ON_ERROR), $ttl);
            }
        };
        return $this;
    }
}
