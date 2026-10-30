<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\PortGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction()
    {
        $result = json_decode((new Backend())->configdRun('portguard status'), true);
        return is_array($result) ? $result : ['error' => gettext('Status could not be read.')];
    }

    /**
     * the Devices seen tab's grid: each device the status script sees, and whether it is listed
     */
    public function searchSeenAction()
    {
        $rows = [];
        foreach (($this->statusAction()['seen'] ?? []) as $device) {
            $mac = (string)($device['mac'] ?? '');
            $ip = (string)($device['ip'] ?? '');
            $rows[] = [
                'id' => $mac . '/' . $ip,
                'interface' => (string)($device['interface'] ?? ''),
                'mac' => $mac,
                'ip' => $ip,
                'vendor' => (string)($device['vendor'] ?? ''),
                'listed' => !empty($device['listed']),
            ];
        }
        return $this->searchRecordsetBase($rows, ['interface', 'mac', 'ip', 'vendor']);
    }

    /**
     * the device list just saved, put into the firewall by apply.php: the alias, then the filter (which
     * registers the rules) and the aliases (which resolve the addresses) reloaded the way Firewall:
     * Aliases reloads them - all in the one action, so `configctl portguard apply` does the same
     */
    public function applyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $result = json_decode((new Backend())->configdRun('portguard apply'), true);
        return is_array($result) ? $result : ['status' => 'failed'];
    }
}
