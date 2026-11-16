#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""Isolate a device that reached a command-and-control list - by its MAC address, for a time.

    isolate.py run                  once a minute (cron.d/portguard) and at the page's Apply: isolate,
                                    let go what expired, and put the list into the firewall if it changed
    isolate.py list [client]        the page's Isolated devices tab, as JSON; the client address the page
                                    is opened from is kept as an exception (below)
    isolate.py undo <mac> [client]  let a device go at once

WHAT IT READS. os-netreport writes /var/db/netreport/infected.json: one entry per address of the
firewall's own networks that os-blocklists blocked on its way to a command-and-control list -
{"<address>": {"first", "last", "count", "list", "mac", "name"}}, "last" the time of the latest blocked
connection, "list" the os-blocklists feed, "mac" and "name" empty where it knows none.

WHAT IT DOES, while "Isolate devices that reach a command-and-control list" (general.auto_isolate,
off by default) is on: every entry whose MAC address is known and whose "last" is within the last
RECENT seconds puts that MAC address on the isolation list, until now + general.isolate_hours (24 by
default). The list is a separate MAC alias, portguard_isolated, written by isolate.php the way
apply.php writes portguard_blocked, blocked both ways by plugins.inc.d/portguard.inc's rules, and the
open connections of its addresses cut by cut.py - the plugin's own way of blocking a MAC address and
cutting its connections, used for a second list. An entry without a MAC address is not isolated, and
the page lists it as such.

NEVER ISOLATED - a fixed exception, checked at every run, for the isolated ones too: the firewall's own
addresses and MAC addresses (ifconfig), its gateways' addresses (config.xml, the routers OPNsense keeps
for dynamic gateways in /tmp, the default routes) and their MAC addresses (ARP and NDP), and every
address the page was opened from in the last MANAGER_DAYS days, with its MAC address - the page passes
its client address ($_SERVER['REMOTE_ADDR']) on each reading.

UNDO lets a device go at once, and it is not isolated again for the same entry: only once
os-netreport records a newer "last" for one of its addresses. An isolation that expires is let go the
same way. Turning the option off lets every isolated device go.

The list is kept in STATE (/var/db/os-portguard/isolate.json), not in config.xml, which is saved only
when the alias changes. The alias is always made from STATE: where STATE is lost - a /var in memory
after a reboot - the alias is emptied and nobody stays isolated with nothing on the page to undo it.

Never fails its caller: prints one JSON object and exits 0; what it could not do is in the answer and
in the system log, under portguard.
"""
import fcntl
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
INFECTED = '/var/db/netreport/infected.json'
STATE_DIR = '/var/db/os-portguard'
STATE = os.path.join(STATE_DIR, 'isolate.json')
LOCK = os.path.join(STATE_DIR, 'isolate.lock')
ALIAS = 'portguard_isolated'
ALIAS_WRITER = '/usr/local/opnsense/scripts/portguard/isolate.php'
IFCONFIG = '/sbin/ifconfig'
ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'
ROUTE = '/sbin/route'
ROUTERS = '/tmp'            # OPNsense's <interface>_router and _routerv6 files: a dynamic gateway's address
TAG = 'portguard'
RECENT = 600                # an entry is acted on while its latest blocked connection is this recent
DEFAULT_HOURS = 24
MAX_HOURS = 720
MANAGER_DAYS = 7            # how long an address the page was opened from stays an exception
WAIT = 10                   # seconds a run waits for another to end
MAC = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')


def log(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def run_cmd(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def norm_mac(mac):
    mac = (mac or '').strip().lower().replace('-', ':')
    return mac if MAC.match(mac) else ''


def norm_ip(addr):
    """An address as one text, without a scope (fe80::1%igb0) or a mask; '' for anything else."""
    try:
        return str(ipaddress.ip_address(str(addr or '').split('%')[0].split('/')[0].strip()))
    except ValueError:
        return ''


def load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def save(path, data):
    """Through a temporary file of this run's own, renamed over it: a reader never meets half a file."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- the settings

def settings():
    """(on, hours) from config.xml - off where it cannot be read or says nothing: off by default."""
    try:
        root = ET.parse(CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None, DEFAULT_HOURS
    general = root.find('OPNsense/PortGuard/general')
    on = general is not None and (general.findtext('auto_isolate') or '0') == '1'
    try:
        hours = int(general.findtext('isolate_hours') or DEFAULT_HOURS) if general is not None else DEFAULT_HOURS
    except ValueError:
        hours = DEFAULT_HOURS
    return on, min(max(hours, 1), MAX_HOURS)


# ---------------------------------------------------------------- the exceptions

def own():
    """The firewall's own addresses and MAC addresses, from ifconfig."""
    addrs, macs = set(), set()
    for line in run_cmd([IFCONFIG, '-a']).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ('inet', 'inet6'):
            ip = norm_ip(parts[1])
            if ip:
                addrs.add(ip)
        elif len(parts) >= 2 and parts[0] in ('ether', 'hwaddr'):
            mac = norm_mac(parts[1])
            if mac:
                macs.add(mac)
    return addrs, macs


def gateways():
    """The gateways' addresses: config.xml's, the routers OPNsense keeps for dynamic ones, and the
    default routes."""
    out = set()
    try:
        root = ET.parse(CONFIG).getroot()
        for item in root.findall('OPNsense/Gateways/gateway_item') + root.findall('gateways/gateway_item'):
            ip = norm_ip(item.findtext('gateway'))
            if ip:
                out.add(ip)
    except (OSError, ET.ParseError):
        pass
    try:
        names = [n for n in os.listdir(ROUTERS) if n.endswith('_router') or n.endswith('_routerv6')]
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(ROUTERS, name), encoding='utf-8', errors='replace') as fh:
                ip = norm_ip(fh.read().strip())
        except OSError:
            continue
        if ip:
            out.add(ip)
    for family in ('-inet', '-inet6'):
        found = re.search(r'gateway:\s*(\S+)', run_cmd([ROUTE, '-n', 'get', family, 'default']))
        ip = norm_ip(found.group(1)) if found else ''
        if ip:
            out.add(ip)
    return out


def neighbours():
    """{address: MAC address} from the ARP and NDP tables now."""
    out = {}
    for line in run_cmd([ARP, '-an']).splitlines():
        found = re.match(r'\S+ \(([^)]+)\) at (\S+)', line)
        if found and norm_ip(found.group(1)) and norm_mac(found.group(2)):
            out[norm_ip(found.group(1))] = norm_mac(found.group(2))
    for line in run_cmd([NDP, '-an']).splitlines():
        parts = line.split()
        if len(parts) >= 2 and norm_ip(parts[0]) and norm_mac(parts[1]):
            out[norm_ip(parts[0])] = norm_mac(parts[1])
    return out


def exceptions(state, now):
    """{'addr': {address: why}, 'mac': {mac: why}} - what is never isolated, each with its reason."""
    addr, mac = {}, {}
    table = neighbours()
    mine, my_macs = own()
    for ip in mine:
        addr[ip] = 'this firewall'
    for m in my_macs:
        mac[m] = 'this firewall'
    for ip in gateways():
        addr.setdefault(ip, 'a gateway')
        if table.get(ip):
            mac.setdefault(table[ip], 'a gateway')
    for ip, seen in (state.get('managers') or {}).items():
        if not isinstance(seen, dict) or now - (seen.get('at') or 0) > MANAGER_DAYS * 86400:
            continue
        addr.setdefault(ip, 'the address this page is opened from')
        for m in filter(None, (norm_mac(seen.get('mac')), table.get(ip))):
            mac.setdefault(m, 'the address this page is opened from')
    return {'addr': addr, 'mac': mac}


def remember_client(state, client, now):
    """The address the page is opened from, with its MAC address now, kept as an exception."""
    ip = norm_ip(client)
    if not ip:
        return False
    managers = state.setdefault('managers', {})
    managers[ip] = {'at': now, 'mac': neighbours().get(ip, '') or (managers.get(ip) or {}).get('mac', '')}
    for old in [k for k, v in managers.items() if now - ((v or {}).get('at') or 0) > MANAGER_DAYS * 86400]:
        del managers[old]
    return True


# ---------------------------------------------------------------- the list

def infected():
    """os-netreport's entries, each with its address in it; {} where there is no file. An entry written
    without a MAC address (os-netreport knows the MAC addresses of its LAN scan only) takes the one the
    ARP or NDP table holds for its address now, if any - a device on another interface, or behind a
    lab link, is still found by its address."""
    data = load(INFECTED, {})
    out = {}
    table = None
    for address, entry in data.items():
        ip = norm_ip(address)
        if ip and isinstance(entry, dict):
            mac = norm_mac(entry.get('mac'))
            if not mac:
                if table is None:
                    table = neighbours()
                mac = table.get(ip, '')
            out[ip] = dict(entry, address=ip, mac=mac)
    return out


def why_not(entry, exc):
    if entry['address'] in exc['addr']:
        return exc['addr'][entry['address']]
    if entry['mac'] in exc['mac']:
        return exc['mac'][entry['mac']]
    return None


def released_last(entries, mac):
    """The newest "last" among os-netreport's entries of this MAC address: an undone or expired device
    is isolated again only for a newer one."""
    return max([int(e.get('last') or 0) for e in entries.values() if e['mac'] == mac] or [0])


def step(state, entries, exc, on, hours, now):
    """One run's decisions, made on STATE: what is isolated, let go, and why some are not. Returns
    (isolated now, let go)."""
    isolated = state.setdefault('isolated', {})
    released = state.setdefault('released', {})
    gone = []
    if not on:
        for mac in list(isolated):
            gone.append(mac)
            del isolated[mac]
        released.clear()
        state['skipped'] = {}
        return [], gone
    for mac, item in list(isolated.items()):
        why = None
        if now >= int(item.get('until') or 0):
            why = 'expired'
        elif mac in exc['mac'] or any(a in exc['addr'] for a in item.get('addresses') or []):
            why = 'an exception'
        if why:
            released[mac] = max(released_last(entries, mac), int(item.get('last') or 0))
            gone.append(mac)
            del isolated[mac]
    skipped = {}
    added = []
    for entry in sorted(entries.values(), key=lambda e: e['address']):
        last = int(entry.get('last') or 0)
        if not entry['mac']:
            continue                    # listed by the page from infected.json: not isolated, no MAC
        if now - last > RECENT:
            continue
        reason = why_not(entry, exc)
        if reason:
            skipped[entry['address']] = {'mac': entry['mac'], 'reason': reason, 'last': last,
                                         'list': entry.get('list', ''), 'name': entry.get('name', '')}
            continue
        mac = entry['mac']
        if mac in isolated:
            item = isolated[mac]
            if entry['address'] not in item['addresses']:
                item['addresses'] = sorted(set(item['addresses']) | {entry['address']})
            item['last'] = max(int(item.get('last') or 0), last)
            continue
        if last <= int(released.get(mac, -1)):
            skipped[entry['address']] = {'mac': mac, 'reason': 'undone', 'last': last,
                                         'list': entry.get('list', ''), 'name': entry.get('name', '')}
            continue
        isolated[mac] = {'addresses': [entry['address']], 'list': entry.get('list', ''),
                         'name': entry.get('name', ''), 'since': now, 'until': now + hours * 3600,
                         'last': last}
        released.pop(mac, None)
        added.append(mac)
    # a let-go entry is remembered while os-netreport keeps an entry of that MAC address
    for mac in [m for m in released if not any(e['mac'] == m for e in entries.values())]:
        del released[mac]
    state['skipped'] = skipped
    return added, gone


def alias_now():
    """The MAC addresses the portguard_isolated alias in config.xml holds now, sorted; [] where it is
    missing or off, None where config.xml cannot be read."""
    try:
        root = ET.parse(CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        if alias.findtext('name') == ALIAS:
            if (alias.findtext('enabled') or '1') != '1':
                return []
            return sorted(filter(None, (norm_mac(m) for m in (alias.findtext('content') or '').split())))
    return []


def put_into_firewall(macs):
    """The alias made to hold these MAC addresses, the filter and aliases reloaded and the
    connections of the isolated devices cut: isolate.php. Its answer, or an error."""
    try:
        out = subprocess.run([ALIAS_WRITER] + sorted(macs), capture_output=True, text=True, timeout=300).stdout
        answer = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as e:
        return {'status': 'failed', 'errors': [str(e)]}
    return answer if isinstance(answer, dict) else {'status': 'failed'}


def commit(state, added, gone, summary):
    """STATE written; the alias rewritten when it does not hold what STATE lists - so a STATE that was
    lost empties it."""
    want = sorted(state.get('isolated', {}))
    have = alias_now()
    if have is not None and want != have:
        answer = put_into_firewall(want)
        summary['firewall'] = answer
        if answer.get('status') != 'ok':
            log('isolation list not put into the firewall: %s' % '; '.join(answer.get('errors') or ['failed']))
    for mac in added:
        item = state['isolated'][mac]
        log('isolated %s (%s): reached %s, until %s' % (mac, ', '.join(item['addresses']), item.get('list') or '?',
            time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(item['until']))))
    for mac in gone:
        log('isolation of %s ended' % mac)
    save(STATE, state)


def do_run(now=None):
    now = int(now if now is not None else time.time())
    on, hours = settings()
    state = load(STATE, {})
    summary = {'run': now, 'on': bool(on)}
    if on is None:
        summary['message'] = 'isolate: config.xml could not be read; nothing changed'
        return summary
    # off, nothing isolated and no alias left: once a minute, nothing to write
    if not on and not state.get('isolated') and not state.get('released') and not alias_now():
        summary['message'] = 'isolate: off'
        return summary
    entries = infected() if on else {}
    exc = exceptions(state, now) if on else {'addr': {}, 'mac': {}}
    added, gone = step(state, entries, exc, on, hours, now)
    summary.update({'isolated': sorted(state['isolated']), 'added': added, 'let_go': gone})
    commit(state, added, gone, summary)
    summary.setdefault('message', 'isolate: %d isolated, %d new, %d let go' % (len(state['isolated']), len(added),
                                                                            len(gone)))
    return summary


def do_list(client, now=None):
    now = int(now if now is not None else time.time())
    on, hours = settings()
    state = load(STATE, {})
    if remember_client(state, client, now):
        save(STATE, state)
    rows = []
    for mac, item in sorted((state.get('isolated') or {}).items()):
        rows.append({'mac': mac, 'addresses': item.get('addresses') or [], 'list': item.get('list', ''),
                     'name': item.get('name', ''), 'since': item.get('since'), 'until': item.get('until')})
    entries = infected()
    others = [{'address': ip, 'mac': '', 'name': e.get('name', ''), 'list': e.get('list', ''),
               'last': e.get('last'), 'reason': 'no MAC'} for ip, e in sorted(entries.items()) if not e['mac']]
    for ip, item in sorted((state.get('skipped') or {}).items()):
        if ip in entries:
            others.append(dict(item, address=ip))
    return {'on': bool(on), 'hours': hours, 'isolated': rows, 'not_isolated': others}


def do_undo(mac, client, now=None):
    now = int(now if now is not None else time.time())
    mac = norm_mac(mac)
    state = load(STATE, {})
    remember_client(state, client, now)
    item = (state.get('isolated') or {}).pop(mac, None) if mac else None
    if item is None:
        save(STATE, state)
        return {'status': 'failed', 'message': 'not isolated: %s' % (mac or 'no MAC address given')}
    state.setdefault('released', {})[mac] = max(released_last(infected(), mac), int(item.get('last') or 0))
    summary = {'status': 'ok', 'mac': mac}
    commit(state, [], [mac], summary)
    if (summary.get('firewall') or {}).get('status') != 'ok':
        summary['status'] = 'failed'
    return summary


def take(lock, wait=WAIT):
    until = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= until:
                return False
            time.sleep(0.5)


def main(argv):
    command = argv[0] if argv else 'run'
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOCK, 'w') as lock:
            if not take(lock):
                print(json.dumps({'status': 'failed', 'message': 'isolate: another run is busy'}))
                return 0
            if command == 'run':
                answer = do_run()
            elif command == 'list':
                answer = do_list(argv[1] if len(argv) > 1 else '')
            elif command == 'undo':
                answer = do_undo(argv[1] if len(argv) > 1 else '', argv[2] if len(argv) > 2 else '')
            else:
                answer = {'status': 'failed', 'message': 'usage: isolate.py run | list [client] | undo <mac> [client]'}
            print(json.dumps(answer, sort_keys=True))
    except Exception as e:      # never fail the caller: cron, configd
        log('isolate stopped: %s' % e)
        print(json.dumps({'status': 'failed', 'message': 'isolate: stopped - %s' % e}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
