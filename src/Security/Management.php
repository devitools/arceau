<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security;

use InvalidArgumentException;

use function Devitools\Arceau\Security\Helper\ip;

use const Devitools\Arceau\Security\Helper\FIREWALL_ALLOW;
use const Devitools\Arceau\Security\Helper\FIREWALL_DENY;

/**
 * Class Management
 *
 * @package Devitools\Arceau\Security
 */
abstract class Management
{
    /**
     * @var string
     */
    private $defaultMode;

    /**
     * @var string
     */
    private $ip;

    /**
     * @var array
     */
    private $ips = [];

    /**
     * @var string
     */
    private $query;

    /**
     * @var array
     */
    private $queries = [];

    /**
     * @var string
     */
    private $template;

    /**
     * Firewall constructor.
     *
     * @param array $settings
     */
    public function __construct(array $settings = [])
    {
        $this->ip = $settings['ip'] ?? ip();
        $this->query = $settings['query'] ?? $_SERVER['QUERY_STRING'] ?? '';

        $this->defaultMode = $settings['defaultMode'] ?? FIREWALL_DENY;
        $this->template = $settings['template'] ?? __DIR__ . '/../../views/403.php';
    }

    /**
     * @param array $settings
     *
     * @return Firewall
     */
    public static function instance(array $settings = []): self
    {
        return new static($settings);
    }

    /**
     * @return string
     */
    public function getDefaultMode(): string
    {
        return $this->defaultMode;
    }

    /**
     * @return string
     */
    public function getTemplate(): string
    {
        return $this->template;
    }

    /**
     * @return array
     */
    public function getIps(): array
    {
        return $this->ips;
    }

    /**
     * @return mixed|string
     */
    public function getIp()
    {
        return $this->ip;
    }

    /**
     * @return string
     */
    public function getQuery(): string
    {
        return $this->query;
    }

    /**
     * @return array
     */
    public function getQueries(): array
    {
        return $this->queries;
    }

    /**
     * @param string $mode
     *
     * @return $this
     */
    public function setDefaultMode(string $mode): self
    {
        $this->defaultMode = $mode;
        return $this;
    }

    /**
     * @param string $filename
     *
     * @return $this
     */
    public function setTemplate(string $filename): self
    {
        $this->template = $filename;
        return $this;
    }

    /**
     * @param array $ips
     *
     * @return $this
     */
    public function mergeIps(array $ips): self
    {
        $this->ips = array_merge($this->ips, $ips);
        return $this;
    }

    /**
     * @param string $ip
     * @param string $mode
     *
     * @return $this
     */
    public function addIp(string $ip, string $mode = FIREWALL_ALLOW): self
    {
        $previous = $this->ips[$ip] ?? null;
        if (isset($previous) && $previous !== $mode) {
            throw new InvalidArgumentException("The ip rule '{$ip}' is already registered with '{$previous}'");
        }
        $this->ips[$ip] = $mode;
        return $this;
    }

    /**
     * @param string[] $ips
     * @param string $mode
     *
     * @return $this
     */
    public function addIps(array $ips, string $mode = FIREWALL_ALLOW): self
    {
        foreach ($ips as $ip) {
            $this->addIp($ip, $mode);
        }
        return $this;
    }

    /**
     * @param string $query
     * @param string $mode
     *
     * @return $this
     */
    public function addQuery(string $query, string $mode = FIREWALL_ALLOW): self
    {
        $previous = $this->queries[$query] ?? null;
        if (isset($previous) && $previous !== $mode) {
            throw new InvalidArgumentException("The query rule '{$query}' is already registered with '{$previous}'");
        }
        $this->queries[$query] = $mode;
        return $this;
    }

    /**
     * @param string[] $queries
     * @param string $mode
     *
     * @return $this
     */
    public function addQueries(array $queries, string $mode = FIREWALL_ALLOW): self
    {
        foreach ($queries as $query) {
            $this->addQuery($query, $mode);
        }
        return $this;
    }

    /**
     * @param array $queries
     *
     * @return $this
     */
    public function mergeQueries(array $queries): self
    {
        $this->queries = array_merge($this->queries, $queries);
        return $this;
    }
}
