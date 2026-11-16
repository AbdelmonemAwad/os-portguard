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

    /**
     * the Isolated devices tab: the devices isolated for reaching a command-and-control list, and those
     * that were not, with why. The address this page is opened from goes with it: isolate.py keeps it as
     * an exception it never isolates (the plan's fixed exception).
     */
    public function isolatedAction()
    {
        $result = json_decode((new Backend())->configdpRun('portguard isolated', [$this->clientAddress()]), true);
        return is_array($result) ? $result : ['error' => gettext('Status could not be read.')];
    }

    /**
     * Undo: an isolated device let go at once, by its MAC address; not isolated again until
     * os-netreport records a newer connection of it to a command-and-control list
     */
    public function releaseAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $mac = strtolower(trim((string)$this->request->getPost('mac')));
        if (!preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $mac)) {
            return ['status' => 'failed', 'message' => 'mac'];
        }
        $result = json_decode((new Backend())->configdpRun('portguard release', [$mac, $this->clientAddress()]), true);
        return is_array($result) ? $result : ['status' => 'failed'];
    }

    /* the address this request came from, as the web server saw it; '' when it is not an address */
    private function clientAddress()
    {
        $address = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        return filter_var($address, FILTER_VALIDATE_IP) !== false ? $address : '';
    }
}
