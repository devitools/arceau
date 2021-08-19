<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security;

use Closure;
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
     * @param Closure|null $callback
     *
     * @return bool
     */
    public function validate(Closure $callback = null): bool
    {
        $isAllowed = $this->getDefaultMode() === FIREWALL_ALLOW;
        $rule = 'default';
        $pattern = '';
        foreach ($this->getItems() as $candidate => $try) {
            $matched = $this->match((string)$candidate);
            if (!$matched) {
                continue;
            }
            $pattern = $candidate;
            $rule = $try;
            break;
        }

        if ($rule !== 'default') {
            $isAllowed = $rule === FIREWALL_ALLOW;
        }

        if (!isset($callback)) {
            return $isAllowed;
        }

        $answer = $callback($this, $isAllowed, $pattern, $rule);
        return $answer ?? $isAllowed;
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
            throw new RuntimeException("{$firewall->getIp()} is not allowed by rule '{$rule}' with pattern '{$pattern}'");
        };
        $this->validate($callback);
    }
}
