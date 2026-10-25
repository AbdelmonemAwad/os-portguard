<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The rules that stop a listed device, registered at every filter reload from the alias this plugin
 * owns (portguard_blocked, scripts/portguard/apply.php), the way os-crowdsec registers its own: never
 * among the owner's rules in Firewall: Rules. Priority 1 puts them before the interface rules - the
 * anti-lockout rule too, so a device listed here cannot reach this page either - and quick, so a
 * block is final. Inbound from the device on every interface, and outbound to it.
 *
 * What this stops is what passes through the firewall. Two devices behind the same switch still reach
 * each other: frames between them never come to the firewall. Blocking those needs the switch, and
 * matching frames by type needs Ethernet rules, which OPNsense's pf.conf does not have (README).
 */

use OPNsense\Firewall\Plugin;

function portguard_firewall(Plugin $fw)
{
    global $config;

    $general = $config['OPNsense']['PortGuard']['general'] ?? [];
    if (($general['enabled'] ?? '1') !== '1') {
        return;
    }
    $alias = null;
    $aliases = $config['OPNsense']['Firewall']['Alias']['aliases']['alias'] ?? [];
    foreach (isset($aliases['name']) ? [$aliases] : $aliases as $item) {
        if (($item['name'] ?? '') === 'portguard_blocked') {
            $alias = $item;
        }
    }
    if ($alias === null || ($alias['enabled'] ?? '1') !== '1') {
        return;
    }
    $log = ($general['log'] ?? '0') === '1';
    foreach (['inet', 'inet6'] as $family) {
        $fw->registerFilterRule(1, [
            'ipprotocol' => $family,
            'descr' => 'Port Guard: blocked devices in',
            'from' => '<portguard_blocked>',
            'direction' => 'in',
            'type' => 'block',
            'log' => $log,
            'quick' => true,
        ]);
        $fw->registerFilterRule(1, [
            'ipprotocol' => $family,
            'descr' => 'Port Guard: blocked devices out',
            'to' => '<portguard_blocked>',
            'direction' => 'out',
            'type' => 'block',
            'log' => $log,
            'quick' => true,
        ]);
    }
}
