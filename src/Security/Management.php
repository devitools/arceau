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
    private $items;

    /**
     * @var string
     */
    private $query;

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
        $this->items = $settings['items'] ?? [];
        $this->query = $settings['query'] ?? $_SERVER['QUERY_STRING'] ?? '';

        $this->defaultMode = $settings['defaultMode'] ?? FIREWALL_DENY;
        $this->template = $settings['template'] ?? __DIR__ . '/../views/403.php';
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
    public function getItems(): array
    {
        return $this->items;
    }

    /**
     * @return mixed|string
     */
    public function getIp()
    {
        return $this->ip;
    }

    /**
     * @return mixed|string
     */
    public function getQuery()
    {
        return $this->query;
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
     * @param string[] $items
     * @param string $mode
     *
     * @return $this
     */
    public function addItems(array $items, string $mode = FIREWALL_ALLOW): self
    {
        foreach ($items as $item) {
            $this->addItem($item, $mode);
        }
        return $this;
    }

    /**
     * @param string $item
     * @param string $mode
     *
     * @return $this
     */
    public function addItem(string $item, string $mode = FIREWALL_ALLOW): self
    {
        $previous = $this->items[$item] ?? null;
        if (isset($previous) && $previous !== $mode) {
            throw new InvalidArgumentException("The item '{$item}' is already registered with '{$previous}'");
        }
        $this->items[$item] = $mode;
        return $this;
    }
}
