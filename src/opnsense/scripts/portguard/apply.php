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
 * left switched off.
 *
 *   apply.php     print a JSON summary; the page's Apply then reloads the filter and the aliases
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\PortGuard\PortGuard;

const NAME = 'portguard_blocked';

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
echo json_encode(['status' => 'ok', 'changes' => $report]) . "\n";
