<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security;

use Closure;
use Devitools\Arceau\Cache\Driver;
use Devitools\Arceau\Cache\Redis;
use Devitools\Arceau\Security\Helper\NginxHelper;
use RuntimeException;
use Throwable;

use const Devitools\Arceau\Security\Helper\FIREWALL_ALLOW;

/**
 * Class Firewall
 *
 * @package Firewall\Security
 */
class Firewall extends Management
{
    /**
     * @see Redis
     */
    use Redis;

    /**
     * @see NginxHelper
     */
    use NginxHelper;

    /**
     * @var Driver
     */
    protected $cacheDriver;

    /**
     * @param bool $allowed
     * @param string $mode
     * @param Closure|null $callback
     *
     * @return bool|mixed
     */
    protected function answer(bool $allowed, string $mode, Closure $callback = null)
    {
        if (!isset($callback)) {
            return $allowed;
        }
        $answer = $callback($this, $allowed, $mode);
        return $answer ?? $allowed;
    }

    /**
     * @param string $pattern
     * @param string $subject
     *
     * @return bool
     */
    private function test(string $pattern, string $subject): bool
    {
        try {
            return (bool)preg_match($pattern, $subject);
        } catch (Throwable $exception) {
        }
        return false;
    }

    /**
     * @param string $key
     *
     * @return array|null
     */
    protected function recover(string $key)
    {
        if (!$this->cacheDriver) {
            return null;
        }
        if (!$this->cacheDriver->has($key)) {
            return null;
        }
        return $this->cacheDriver->get($key);
    }

    /**
     * @param string $key
     * @param array $value
     *
     * @return $this
     */
    protected function register(string $key, array $value): self
    {
        if (!$this->cacheDriver) {
            return $this;
        }
        $this->cacheDriver->set($key, $value);
        return $this;
    }

    /**
     * @param Closure|null $callback
     *
     * @return bool
     */
    public function validate(Closure $callback = null): bool
    {
        $validated = $this->validateQuery();
        if ($validated) {
            list($allowed, $mode) = $validated;
            return $this->answer($allowed, $mode, $callback);
        }

        $validated = $this->validateIp();
        list($allowed, $mode) = $validated;
        return $this->answer($allowed, $mode, $callback);
    }

    /**
     * @return array|null
     */
    protected function validateIp()
    {
        $ip = $this->getIp();
        $cached = $this->recover($ip);
        if (isset($cached)) {
            list($allowed, $mode) = $cached;
            return [$allowed, $mode];
        }

        $matched = $this->matchIp($ip);
        if (isset($matched)) {
            $mode = $matched;
            $allowed = $mode === FIREWALL_ALLOW;
        }

        if (!isset($allowed, $mode)) {
            $mode = 'default';
            $allowed = $this->getDefaultMode() === FIREWALL_ALLOW;
        }

        $this->register($ip, [$allowed, $mode]);
        return [$allowed, $mode];
    }

    /**
     * @param string $ip
     *
     * @return string|null
     */
    private function matchIp(string $ip)
    {
        $candidates = $this->getIps();
        foreach ($candidates as $candidate => $mode) {
            $pattern = '/' . str_replace('\*', '(.*)', preg_quote($candidate)) . '/';
            $match = $this->test($pattern, $ip);
            if (!$match) {
                continue;
            }
            return $mode;
        }
        return null;
    }

    /**
     * @return array|null
     */
    protected function validateQuery()
    {
        $query = $this->getQuery();
        $cached = $this->recover($query);
        if (isset($cached)) {
            list($allowed, $mode) = $cached;
            return [$allowed, $mode];
        }

        $matched = $this->matchQuery($query);
        if (!isset($matched)) {
            return null;
        }
        $mode = $matched;
        $allowed = $mode === FIREWALL_ALLOW;

        $this->register($query, [$allowed, $mode]);
        return [$allowed, $mode];
    }

    /**
     * @param string $query
     *
     * @return string|null
     */
    private function matchQuery(string $query)
    {
        $candidateToPattern = static function (string $query) {
            return '/' .
                str_replace('*', '(.*)', str_replace('/', '\/', $query)) .
                '|' .
                str_replace('*', '(.*)', str_replace('/', '%2F', $query)) .
                '/';
        };
        $candidates = $this->getQueries();
        foreach ($candidates as $candidate => $mode) {
            $pattern = $candidateToPattern($candidate);
            $match = $this->test($pattern, $query);
            if (!$match) {
                continue;
            }
            return $mode;
        }
        return null;
    }

    /**
     * @throw RuntimeException
     */
    public function check()
    {
        $callback = static function (Firewall $firewall, bool $result, string $mode) {
            if ($result) {
                return;
            }

            http_response_code(403);

            $filename = $firewall->getTemplate();
            if (file_exists($filename)) {
                $template = require $filename;
            }
            if (!isset($template)) {
                exit();
            }
            if (is_callable($template)) {
                $template($firewall, $mode);
            }
            exit();
        };
        $this->validate($callback);
    }

    /**
     * @throw RuntimeException
     */
    public function handle()
    {
        $callback = static function (Firewall $firewall, bool $result, string $pattern, string $mode) {
            if ($result) {
                return;
            }
            throw new RuntimeException(
                "{$firewall->getIp()} is not allowed by rule '{$mode}' with pattern '{$pattern}'"
            );
        };
        $this->validate($callback);
    }

    /**
     * @return $this
     */
    public function debug(): self
    {
        file_put_contents('php://stdout', "{$this->getIp()} | {$this->getQuery()}");
        return $this;
    }
}
