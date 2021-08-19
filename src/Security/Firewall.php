<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security;

use Closure;
use Devitools\Arceau\Cache\Driver;
use Devitools\Arceau\Cache\Redis;
use InvalidArgumentException;
use RuntimeException;

use const Devitools\Arceau\Security\Helper\FIREWALL_ALLOW;
use const Devitools\Arceau\Security\Helper\FIREWALL_DENY;

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
     * @var Driver
     */
    protected $cacheDriver;

    /**
     * @var int
     */
    protected $secondsToExpire = 60;

    /**
     * @param int $secondsToExpire
     *
     * @return $this
     */
    public function setSecondsToExpire(int $secondsToExpire): self
    {
        $this->secondsToExpire = $secondsToExpire;
        return $this;
    }

    /**
     * @param string $filename
     *
     * @return $this
     */
    public function addNginxFile(string $filename): self
    {
        if (!file_exists($filename)) {
            throw new InvalidArgumentException('Invalid filename');
        }

        if (is_dir($filename)) {
            throw new InvalidArgumentException('Invalid filename');
        }

        // https://regex101.com/r/P2ZYjM/4
        foreach (file($filename) as $line) {
            $pattern = '/^[^#]*?(allow|deny) ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)[;\/]/m';
            preg_match($pattern, $line, $matches);
            if (!isset($matches[1], $matches[2])) {
                continue;
            }
            [, $mode, $item] = $matches;
            if (!in_array($mode, [FIREWALL_ALLOW, FIREWALL_DENY], true)) {
                continue;
            }
            $this->addItem($item, $mode);
        }
        return $this;
    }

    /**
     * @param string $candidate
     *
     * @return string|null
     */
    private function match(string $candidate): ?string
    {
        $pieces = explode('query:', $candidate);
        if (count($pieces) === 1) {
            $pattern = '/' . str_replace('\*', '(.*)', preg_quote($candidate)) . '/';
            preg_match($pattern, $this->getIp(), $matches);
            return $matches[0] ?? null;
        }

        if (count($pieces) !== 2) {
            return null;
        }

        $query = $pieces[1];
        $pattern = '/' .
            str_replace('*', '(.*)', str_replace('/', '\/', $query)) .
            '|' .
            str_replace('*', '(.*)', str_replace('/', '%2F', $query)) .
            '/';
        preg_match($pattern, $this->getQuery(), $matches);
        return $matches[0] ?? null;
    }

    /**
     * @return array|null
     */
    protected function recover(): ?array
    {
        if (!$this->cacheDriver) {
            return null;
        }
        $keys = [$this->getIp(), $this->getQuery()];
        foreach ($keys as $key) {
            if (!$this->cacheDriver->has($key)) {
                continue;
            }
            return $this->cacheDriver->get($key);
        }
        return null;
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
        $this->cacheDriver->set($key, $value, $this->secondsToExpire);
        return $this;
    }

    /**
     * @param Closure|null $callback
     *
     * @return bool
     */
    public function validate(Closure $callback = null): bool
    {
        $cached = $this->recover();
        if (isset($cached)) {
            [$allowed, $pattern, $mode] = $cached;
            return $this->answer($allowed, $pattern, $mode, $callback);
        }

        $pattern = '';
        $mode = 'default';
        foreach ($this->getItems() as $patternCandidate => $modeCandidate) {
            $key = $this->match((string)$patternCandidate);
            if (!isset($key)) {
                continue;
            }

            $pattern = $patternCandidate;
            $mode = $modeCandidate;
            break;
        }

        $allowed = $this->getDefaultMode() === FIREWALL_ALLOW;
        if ($mode !== 'default') {
            $allowed = $mode === FIREWALL_ALLOW;
        }

        if (isset($key)) {
            $this->register($key, [$allowed, $pattern, $mode]);
        }

        return $this->answer($allowed, $pattern, $mode, $callback);
    }

    /**
     * @param bool $allowed
     * @param string $pattern
     * @param string $mode
     * @param Closure|null $callback
     *
     * @return bool|mixed
     */
    protected function answer(bool $allowed, string $pattern, string $mode, ?Closure $callback)
    {
        if (!isset($callback)) {
            return $allowed;
        }
        $answer = $callback($this, $allowed, $pattern, $mode);
        return $answer ?? $allowed;
    }

    /**
     * @throw RuntimeException
     */
    public function handle(): void
    {
        $callback = static function (Firewall $firewall, bool $result, string $pattern, string $mode) {
            if ($result) {
                return;
            }

            http_response_code(403);

            $filename = $firewall->getTemplate();
            if (file_exists($filename)) {
                /** @noinspection PhpIncludeInspection */
                $template = require $filename;
            }
            if (!isset($template)) {
                exit();
            }
            if (is_callable($template)) {
                $template($firewall, $pattern, $mode);
            }
            exit();
        };
        $this->validate($callback);
    }

    /**
     * @throw RuntimeException
     */
    public function check(): void
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
}
