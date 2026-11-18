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
 *
 * The isolated devices (2026-11-17) the same way, from a second alias, portguard_isolated, which
 * scripts/portguard/isolate.py fills with the devices os-netreport saw reaching a command-and-control
 * list: registered while automatic isolation is on, whether or not the blocked devices are.
 */

use OPNsense\Firewall\Plugin;

function portguard_firewall(Plugin $fw)
{
    global $config;

    $general = $config['OPNsense']['PortGuard']['general'] ?? [];
    $log = ($general['log'] ?? '0') === '1';
    if (($general['enabled'] ?? '1') === '1' && portguard_alias_on('portguard_blocked')) {
        portguard_block($fw, 'portguard_blocked', 'Port Guard: blocked devices', $log);
    }
    if (($general['auto_isolate'] ?? '0') === '1' && portguard_alias_on('portguard_isolated')) {
        portguard_block($fw, 'portguard_isolated', 'Port Guard: isolated devices', $log);
    }
}

/* whether the alias by this name is in config.xml and on */
function portguard_alias_on($name)
{
    global $config;

    $aliases = $config['OPNsense']['Firewall']['Alias']['aliases']['alias'] ?? [];
    foreach (isset($aliases['name']) ? [$aliases] : $aliases as $item) {
        if (($item['name'] ?? '') === $name) {
            return ($item['enabled'] ?? '1') === '1';
        }
    }
    return false;
}

/* inbound from the alias's addresses and outbound to them, both families, quick, before the interface rules */
function portguard_block(Plugin $fw, $alias, $descr, $log)
{
    foreach (['inet', 'inet6'] as $family) {
        $fw->registerFilterRule(1, [
            'ipprotocol' => $family,
            'descr' => $descr . ' in',
            'from' => '<' . $alias . '>',
            'direction' => 'in',
            'type' => 'block',
            'log' => $log,
            'quick' => true,
        ]);
        $fw->registerFilterRule(1, [
            'ipprotocol' => $family,
            'descr' => $descr . ' out',
            'to' => '<' . $alias . '>',
            'direction' => 'out',
            'type' => 'block',
            'log' => $log,
            'quick' => true,
        ]);
    }
}
