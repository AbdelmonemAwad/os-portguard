#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
What the page shows, as one JSON object: the devices the firewall sees - interface, MAC address, IP
address, maker - from OPNsense's own list_hosts.py (its host discovery's last day where it is on,
else the ARP and NDP tables now); which of them are listed; the addresses pf blocks now for the listed devices;
and the rules' counters.

    status.py

Read only.
"""

import json
import re
import subprocess
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
LIST_HOSTS = '/usr/local/opnsense/scripts/interfaces/list_hosts.py'
PFCTL = '/sbin/pfctl'
TABLE = 'portguard_blocked'


def run(args, timeout=60):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def norm(mac):
    return (mac or '').lower().replace('-', ':')


def main():
    try:
        root = ET.parse(CONFIG).getroot()
    except (OSError, ET.ParseError):
        print(json.dumps({'error': 'config.xml could not be read'}))
        return
    general = root.find('OPNsense/PortGuard/general')
    enabled = general is None or (general.findtext('enabled') or '1') == '1'
    # a device is listed - blocked - only while Port Guard is on: off, the page marked the devices it
    # names as blocked all the same (2026-10-29)
    listed = []
    if enabled:
        for device in root.findall('OPNsense/PortGuard/devices/device'):
            if (device.findtext('enabled') or '1') == '1' and device.findtext('mac'):
                listed.append(norm(device.findtext('mac')))

    # the firewall's own interface names, for the device table
    names = {}
    for iface in list(root.find('interfaces') if root.find('interfaces') is not None else []):
        if iface.findtext('if'):
            names[iface.findtext('if')] = iface.findtext('descr') or iface.tag.upper()

    try:
        # a day of host discovery, or the ARP and NDP tables now (-n adds NDP where there is no discovery)
        hosts = json.loads(run(['/usr/local/bin/python3', LIST_HOSTS, '-v', '-n', '--last-seen-window', '86400']) or '{}')
    except ValueError:
        hosts = {}
    seen = []
    for row in hosts.get('rows', []):
        mac = norm(row[1] if len(row) > 1 else '')
        seen.append({
            'interface': names.get(row[0], row[0]), 'mac': mac, 'ip': row[2] if len(row) > 2 else '',
            'vendor': row[3] if len(row) > 3 else '',
            'listed': any(mac.startswith(prefix) for prefix in listed),
        })

    counters = {}
    verbose = run([PFCTL, '-vvs', 'Tables'])
    block = re.search(r'^(\S+)\s+' + TABLE + r'\n((?:\s+.*\n?)*)', verbose, re.M)
    if block:
        for direction, packets in re.findall(r'(In|Out)/Block:\s+\[ Packets: (\d+)', block.group(2)):
            counters[direction.lower()] = int(packets)
    # The addresses pf blocks now: the table's, while a rule uses it - its flags carry r (referenced).
    # A table outlives its alias and its rules, and with no device left it went on holding the old
    # addresses, which the page counted as blocked (2026-10-29).
    table = []
    if block and 'r' in block.group(1):
        table = [line.strip() for line in run([PFCTL, '-t', TABLE, '-T', 'show']).splitlines() if line.strip()]

    print(json.dumps({
        'enabled': enabled,
        'source': hosts.get('source'),
        'listed': listed,
        'seen': seen,
        'blocked_now': table,
        'counters': counters,
    }))


if __name__ == '__main__':
    main()
