#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the isolation alias hold the MAC addresses isolate.py names: portguard_isolated, a MAC address
 * alias of its own beside portguard_blocked, written the way apply.php writes that one. OPNsense
 * resolves it into the addresses the ARP and NDP tables (or host discovery) have seen each device use;
 * plugins.inc.d/portguard.inc blocks it both ways while automatic isolation is on. With no MAC address
 * left the alias is removed - switched off instead while something else in config.xml names it - and
 * pf's table of it emptied.
 *
 * Then what apply.php does after its alias: the filter reloaded (the rules), its template and the
 * aliases (the addresses), and cut.py, which cuts the open connections of the addresses the table
 * has just gained.
 *
 *   isolate.php [mac ...]     print a JSON summary; called by isolate.py only
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

const NAME = 'portguard_isolated';

$macs = [];
foreach (array_slice($argv, 1) as $arg) {
    $mac = strtolower(str_replace('-', ':', trim($arg)));
    if (preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $mac)) {
        $macs[] = $mac;
    }
}
$macs = array_values(array_unique($macs));
sort($macs);

$model = new Alias();
$node = $model->getByName(NAME);
$report = [];
if (empty($macs)) {
    if ($node !== null) {
        $text = file_get_contents('/conf/config.xml');
        if (preg_match_all('/\b' . NAME . '\b/', $text) > 1) {
            $node->enabled = '0';
            $report[] = NAME . ': no device isolated, but named elsewhere in the configuration - switched off, not removed';
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
    $node->description = 'Port Guard: isolated devices';
    $report[] = count($macs) . ' device(s)';
}

if (empty($report)) {
    echo json_encode(['status' => 'ok', 'changes' => []]) . "\n";
    exit(0);
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
    /* pf's table outlives its alias, as portguard_blocked's did (apply.php) */
    exec('/sbin/pfctl -t ' . NAME . ' -T flush 2>&1');
}

$backend = new Backend();
$backend->configdRun('filter reload skip_alias');
$backend->configdRun('template reload OPNsense/Filter');
$backend->configdRun('filter refresh_aliases');
$cut = json_decode($backend->configdRun('portguard cut'), true);

echo json_encode(['status' => 'ok', 'changes' => $report, 'cut' => is_array($cut) ? $cut : null]) . "\n";
