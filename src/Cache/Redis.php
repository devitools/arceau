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
     * @param int $secondsToExpire
     *
     * @return $this
     */
    public function configureRedis(string $host, string $port, int $secondsToExpire): self
    {
        if (isset($this->cacheDriver)) {
            throw new RuntimeException("The driver '{$this->cacheDriver->name()}' is already configured");
        }

        $this->cacheDriver = new class ($host, $port, $secondsToExpire) implements Driver {
            /**
             * @var Connection
             */
            private $connection;

            /**
             * @var string
             */
            private $host;

            /**
             * @var string
             */
            private $port;

            /**
             * @var int
             */
            private $ttl;

            /**
             *  Anonymous constructor.
             *
             * @param string $host
             * @param string $port
             * @param int $secondsToExpire
             */
            public function __construct(string $host, string $port, int $secondsToExpire = 60)
            {
                $this->host = $host;
                $this->port = $port;
                $this->ttl = $secondsToExpire;
            }

            /**
             * @return Connection
             */
            protected function connection(): Connection
            {
                if (!$this->connection) {
                    $redis = new Connection();
                    $connected = $redis->connect($this->host, (int)$this->port, 1, NULL, 100);
                    $redis->setOption(Connection::OPT_SERIALIZER, Connection::SERIALIZER_JSON);
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
                return $this->connection()->get($key);
            }

            /**
             * @param string $key
             * @param $value
             *
             * @return bool
             */
            public function set(string $key, $value): bool
            {
                return $this->connection()->set($key, $value, $ttl ?? $this->ttl);
            }
        };
        return $this;
    }
}
