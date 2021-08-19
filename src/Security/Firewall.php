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
     * @return bool
     */
    private function match(string $candidate): bool
    {
        $pieces = explode('query:', $candidate);
        if (count($pieces) === 1) {
            $pattern = '/' . str_replace('\*', '(.*)', preg_quote($candidate)) . '/';
            $match = preg_match($pattern, $this->getIp(), $matches);
            return (bool)$match;
        }

        if (count($pieces) !== 2) {
            return false;
        }

        $query = $pieces[1];
        $pattern = '/' .
            str_replace('*', '(.*)', str_replace('/', '\/', $query)) .
            '|' .
            str_replace('*', '(.*)', str_replace('/', '%2F', $query)) .
            '/';
        $match = preg_match($pattern, $this->getQuery(), $matches);
        return (bool)$match;
    }

    /**
     * @param string $key
     *
     * @return mixed|null
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
     * @param bool $value
     *
     * @return $this
     */
    protected function register(string $key, bool $value): self
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
        $pattern = '';
        $rule = 'default';
        foreach ($this->getItems() as $patternCandidate => $ruleCandidate) {
            $cached = $this->recover($patternCandidate);
            if (isset($cached)) {
                $pattern = $patternCandidate;
                $rule = $ruleCandidate;
                return $this->answer($cached, $pattern, $rule, $callback);
            }

            $matched = $this->match((string)$patternCandidate);
            if (!$matched) {
                continue;
            }

            $pattern = $patternCandidate;
            $rule = $ruleCandidate;
            break;
        }

        $allowed = $this->getDefaultMode() === FIREWALL_ALLOW;
        if ($rule !== 'default') {
            $allowed = $rule === FIREWALL_ALLOW;
        }

        $this->register($pattern, $allowed);

        return $this->answer($allowed, $pattern, $rule, $callback);
    }

    /**
     * @param bool $allowed
     * @param string $pattern
     * @param string $rule
     * @param Closure|null $callback
     *
     * @return bool|mixed
     */
    protected function answer(bool $allowed, string $pattern, string $rule, ?Closure $callback)
    {
        if (!isset($callback)) {
            return $allowed;
        }
        $answer = $callback($this, $allowed, $pattern, $rule);
        return $answer ?? $allowed;
    }

    /**
     * @throw RuntimeException
     */
    public function handle(): void
    {
        $callback = static function (Firewall $firewall, bool $result, string $pattern, string $rule) {
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
                $template($firewall, $pattern, $rule);
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
        $callback = static function (Firewall $firewall, bool $result, string $pattern, string $rule) {
            if ($result) {
                return;
            }
            throw new RuntimeException(
                "{$firewall->getIp()} is not allowed by rule '{$rule}' with pattern '{$pattern}'"
            );
        };
        $this->validate($callback);
    }
}
