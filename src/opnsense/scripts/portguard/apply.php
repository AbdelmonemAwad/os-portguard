#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the alias say what the device list says: one MAC address alias, portguard_blocked, holding
 * every enabled device's address. OPNsense resolves a MAC alias into the IPv4 and IPv6 addresses the
 * firewall's ARP and NDP tables (or its host discovery) have seen that device use, and keeps them
 * current; plugins.inc.d/portguard.inc blocks that table both ways. With no device listed, or the
 * plugin off, the alias is removed - unless something else in config.xml still names it, when it is
 * left switched off - and pf's table of it emptied.
 *
 * Then the rest of what puts the list into the firewall, here rather than in the page's controller,
 * so `configctl portguard apply` does the whole job (2026-10-29: alone it wrote the alias and put no
 * rule into pf): the filter reloaded, which registers the rules; the filter's template and the
 * aliases, which resolve the addresses; and a first round of cut.py, which cuts the connections the
 * devices listed already have open - a rule stops only new ones. And a run of isolate.py, so that
 * automatic isolation turned on or off takes effect at Apply rather than at the next minute.
 *
 *   apply.php     print a JSON summary (the page's Apply, and configctl portguard apply)
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\PortGuard\PortGuard;

const NAME = 'portguard_blocked';
/* the isolated devices' alias: external, its table kept by isolate.py with pfctl (2026-11-17) */
const ISOLATED = 'portguard_isolated';

$settings = new PortGuard();
$macs = [];
if ((string)$settings->general->enabled === '1') {
    foreach ($settings->devices->device->iterateItems() as $device) {
        if ((string)$device->enabled === '1') {
            $macs[] = strtolower(str_replace('-', ':', (string)$device->mac));
        }
    }
}
$macs = array_values(array_unique($macs));

$model = new Alias();
$node = $model->getByName(NAME);
$report = [];
if (empty($macs)) {
    if ($node !== null) {
        $text = file_get_contents('/conf/config.xml');
        if (preg_match_all('/\b' . NAME . '\b/', $text) > 1) {
            $node->enabled = '0';
            $report[] = NAME . ': no device listed, but named elsewhere in the configuration - switched off, not removed';
        } else {
            foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
                if ((string)$alias->name === NAME) {
                    $model->aliases->alias->del($uuid);
                }
            }
            $report[] = NAME . ': removed';
        }
    }
} else {
    if ($node === null) {
        $node = $model->aliases->alias->Add();
        $node->name = NAME;
        $report[] = NAME . ': added';
    } else {
        $report[] = NAME . ': updated';
    }
    $node->enabled = '1';
    $node->type = 'mac';
    $node->content = implode("\n", $macs);
    $node->counters = '1';
    $node->description = 'Port Guard: blocked devices';
    $report[] = count($macs) . ' device(s)';
}

/*
 * The isolated devices (2026-11-17): portguard_isolated, an external alias - OPNsense's "External
 * (advanced)", its table's addresses kept by isolate.py with pfctl, so that an isolation writes no
 * config.xml and reloads no filter - there while automatic isolation is on, for its rules
 * (plugins.inc.d/portguard.inc); removed, and its table emptied, when it is off. config.xml is saved
 * for it here, at Apply, never at an isolation.
 */
$isolating = (string)$settings->general->auto_isolate === '1';
$inode = $model->getByName(ISOLATED);
$isolated_gone = false;
if ($isolating) {
    if ($inode === null) {
        $inode = $model->aliases->alias->Add();
        $inode->name = ISOLATED;
        $report[] = ISOLATED . ': added';
    } elseif ((string)$inode->type !== 'external' || (string)$inode->enabled !== '1') {
        $report[] = ISOLATED . ': made external';
    }
    $inode->enabled = '1';
    $inode->type = 'external';
    $inode->content = '';
    $inode->counters = '1';
    $inode->description = 'Port Guard: isolated devices (kept by isolate.py)';
} elseif ($inode !== null) {
    $text = file_get_contents('/conf/config.xml');
    if (preg_match_all('/\b' . ISOLATED . '\b/', $text) > 1) {
        $inode->enabled = '0';
        $report[] = ISOLATED . ': automatic isolation off, but named elsewhere in the configuration - switched off, not removed';
    } else {
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            if ((string)$alias->name === ISOLATED) {
                $model->aliases->alias->del($uuid);
            }
        }
        $report[] = ISOLATED . ': removed';
    }
    $isolated_gone = true;
}

$messages = [];
foreach ($model->performValidation() as $message) {
    $messages[] = $message->getField() . ': ' . $message->getMessage();
}
if (!empty($messages)) {
    echo json_encode(['status' => 'failed', 'changes' => [], 'errors' => $messages]) . "\n";
    exit(0);
}
$model->serializeToConfig();
Config::getInstance()->save();

if (empty($macs)) {
    /*
     * pf's table outlives its alias: after the last device was removed it went on holding the
     * addresses (2026-10-29), no rule using it, and the page counted them as blocked. Emptied, it holds
     * nothing a rule could use again.
     */
    exec('/sbin/pfctl -t ' . NAME . ' -T flush 2>&1');
}
if ($isolated_gone) {
    /* the isolated devices' table outlives its alias as the blocked devices' does */
    exec('/sbin/pfctl -t ' . ISOLATED . ' -T flush 2>&1');
}

/* the order Firewall: Aliases and the page's Apply always used: the filter, its template, the aliases */
$backend = new Backend();
$backend->configdRun('filter reload skip_alias');
$backend->configdRun('template reload OPNsense/Filter');
$backend->configdRun('filter refresh_aliases');
/* then the cut, once the table holds the addresses the aliases' refresh resolved */
$cut = json_decode($backend->configdRun('portguard cut'), true);
$isolate = json_decode($backend->configdRun('portguard isolate'), true);

echo json_encode(['status' => 'ok', 'changes' => $report, 'cut' => is_array($cut) ? $cut : null,
    'isolate' => is_array($isolate) ? $isolate : null]) . "\n";
