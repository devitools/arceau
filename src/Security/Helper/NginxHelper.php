<?php

declare(strict_types=1);

namespace Devitools\Arceau\Security\Helper;

use InvalidArgumentException;

/**
 * Class NginxHelper
 *
 * @package Devitools\Arceau\Security\Helper
 */
trait NginxHelper
{
    /**
     * @param string $filename
     *
     * @return $this
     */
    public function addIpsFromNginxFile(string $filename): self
    {
        if (!file_exists($filename)) {
            throw new InvalidArgumentException('Invalid filename');
        }

        if (is_dir($filename)) {
            throw new InvalidArgumentException('Invalid filename');
        }

        $ips = [];
        // https://regex101.com/r/P2ZYjM/5
        foreach (file($filename) as $line) {
            $pattern = '/^[^#]*?(allow|deny)[\s]+([\d.*]*)/';
            preg_match($pattern, $line, $matches);
            if (!isset($matches[1], $matches[2])) {
                continue;
            }
            [, $mode, $item] = $matches;
            if (!in_array($mode, [FIREWALL_ALLOW, FIREWALL_DENY], true)) {
                continue;
            }
            $ips[$item] = $mode;
        }
        $this->mergeIps($ips);

        return $this;
    }
}
