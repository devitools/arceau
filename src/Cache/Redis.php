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
             * @param int $ttl
             *
             * @return bool
             */
            public function set(string $key, $value, int $ttl = 60): bool
            {
                return $this->connection()->set($key, $value, $ttl);
            }
        };
        return $this;
    }
}
