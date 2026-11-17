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
connection, "list" the os-blocklists feed, "mac" and "name" empty where it knows none. config.xml is read
once a run, whole, under the shared lock OPNsense's own readers take (read_config()), and that one
reading serves the whole run; a run that cannot read it changes nothing.

WHAT IT DOES, while "Isolate devices that reach a command-and-control list" (general.auto_isolate,
off by default) is on: every entry whose device is known (WHICH DEVICE, below) and whose "last" is
within the last RECENT seconds puts that device's MAC address on the isolation list, until now +
general.isolate_hours (24 by default). The firewall blocks it through an alias of its own,
portguard_isolated: an external alias (OPNsense's "External (advanced)"), which apply.php makes at the
page's Apply while automatic isolation is on and plugins.inc.d/portguard.inc's rules block both ways.
Its table is kept here, with pfctl, at every run (held()): for each isolated MAC address, the addresses
that reached the list, the ones ARP and NDP show for it then, and every one they showed during its
isolation - a device quiet for a while loses its ARP entry, and is still held when it speaks again - but
never a link-local address (a table has no scope), an exception's, or one ARP or NDP shows under another
MAC address then. An address a device takes is held from the next run, within a minute; cut.py cuts the
open connections of the addresses the table gains. So an isolation writes nothing into config.xml (no
backup pushed out, nothing saved over a change made in the GUI meanwhile) and reloads no filter, and a
firewall that takes over in HA starts with an empty table. An entry without a MAC address that ARP or
NDP does not know either is not isolated, and the page lists it as such.

A SHARED MAC ADDRESS - one ARP shows with more than one IPv4 address, as a repeater that puts its own MAC
address on its clients' traffic is shown - is isolated by the addresses that reached the list only; one
that shows a second IPv4 address during its isolation keeps what it had alone as well, and takes no new
address from then on. A router that translates addresses shows one IPv4 address and is isolated whole.

NEVER ISOLATED - a fixed exception, checked at every run: the firewall's own addresses and MAC addresses
(ifconfig), its gateways' addresses (config.xml, the routers OPNsense keeps for dynamic gateways in
/tmp, the default routes), its HA peer (config.xml's hasync), every address logged in to its SSH (utmpx,
as who(1) prints it) or to its web GUI within the GUI's session timeout (the audit log's logins), every
address the page was opened from in the last MANAGER_DAYS days - the page passes its client address
($_SERVER['REMOTE_ADDR']) on each reading - and the MAC addresses ARP and NDP show at any of those. A
connection is not a login: a device scanning the GUI's or SSH's port opens one. A link-local address
counts for none of these: fe80::1 is a neighbour of every segment, and an isolated device keeps its
own, which no table holds.

ONCE ISOLATED, a device is let go only when its isolation ends, by Undo, when the option is turned off,
or when its MAC address turns out to be the firewall's own - never for something it can do itself: an
address it takes (two IPv4 addresses make a MAC address shared), an exception's address it answers ARP
for, a login. An exception's address it shows is kept out of the table instead.

UNDO lets a device go at once, and it is not isolated again before its isolation would have ended (a
device taken for infected by mistake keeps reaching the list, and would be isolated again the next
minute), nor after that for the same entry: only once os-netreport records a newer "last" for one of
its addresses. An isolation that expires is let go the same way, but for the end. Turning the option
off lets every isolated device go.

WHICH DEVICE. An entry's device is the MAC address ARP or NDP shows at its address, where they show one -
the kernel's view now, of a connection made in the last RECENT seconds - and otherwise the one
os-netreport names: os-netreport takes an address's MAC address from its own device scan and never
clears it, so an address that moved before its scan saw the new holder is named for the device it had
before (infected()). Found once for the entry's address and "last", either way, it is kept while that
"last" is the same (STATE's macs): a device that later gets that address is not taken for it, and an
entry ARP does not answer for in one run keeps its device. os-netreport's name for the entry goes with
the device it names, and with no other.

The list is kept in STATE (/var/db/os-portguard/isolate.json), not in config.xml. The table is always
made from STATE: where STATE is lost - a /var in memory after a reboot - the table is emptied and nobody
stays isolated with nothing on the page to undo it.

Never fails its caller: prints one JSON object and exits 0; what it could not do is in the answer and
in the system log, under portguard.
"""
import calendar
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
IFCONFIG = '/sbin/ifconfig'
ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'
ROUTE = '/sbin/route'
PFCTL = '/sbin/pfctl'
WHO = '/usr/bin/who'
CUT = '/usr/local/opnsense/scripts/portguard/cut.py'
ROUTERS = '/tmp'            # OPNsense's <interface>_router and _routerv6 files: a dynamic gateway's address
# OPNsense's audit log, a file a day: where its web GUI writes each login (os-netreport's alerts.py reads
# its failed ones in the same file, its AUDIT_LOG)
AUDIT_LOG = '/var/log/audit/audit_{day}.log'
AUDIT_READ = 16 * 1024 * 1024   # bytes read from the end of one day's audit log at most
GUI_MINUTES = 240               # OPNsense's GUI session timeout where system/webgui/session_timeout is empty
TAG = 'portguard'
RECENT = 600                # an entry is acted on while its latest blocked connection is this recent
DEFAULT_HOURS = 24
MAX_HOURS = 720
MANAGER_DAYS = 7            # how long an address the page was opened from stays an exception
WAIT = 10                   # seconds a run waits for another to end
AHEAD = 300                 # a "last" further ahead of this clock than this is no recent connection
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
    """A MAC address as one text; '' for anything else, and for a group address (broadcast,
    multicast: the first octet's lowest bit) or none at all (zeros), which no one device has."""
    mac = (mac or '').strip().lower().replace('-', ':')
    if not MAC.match(mac) or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
        return ''
    return mac


def norm_ip(addr):
    """An address as one text, without a scope (fe80::1%igb0) or a mask, an IPv4 address an IPv6
    one carries (::ffff:192.0.2.5) as IPv4; '' for anything else."""
    try:
        ip = ipaddress.ip_address(str(addr or '').split('%')[0].split('/')[0].strip())
    except ValueError:
        return ''
    return str(ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip)


def number(value):
    """A time as os-netreport or STATE keeps it, as an integer; 0 for anything else (a date written as
    text, a list): one bad value must stop neither a run nor an undo."""
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def listed(value):
    """A list of texts as STATE keeps it; [] for anything else."""
    return [str(v) for v in value] if isinstance(value, list) else []


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


def take(fh, mode=fcntl.LOCK_EX, wait=None):
    """A lock on an open file, or False after `wait` seconds (WAIT where none is given)."""
    until = time.monotonic() + (WAIT if wait is None else wait)
    while True:
        try:
            fcntl.flock(fh, mode | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= until:
                return False
            time.sleep(0.5)


# ---------------------------------------------------------------- the settings

def read_config(wait=None):
    """config.xml's root, read whole under a shared lock, once for a whole run; None where it cannot be
    read in time or does not parse. OPNsense rewrites the file in place - Config::save() truncates it and
    writes it again while it holds an exclusive lock on it (Config.php:743-767) - and its own readers take
    a shared one for that reason (Config.php:372-394); this is the same flock(2) lock. Read here in
    several pieces, a rewrite between two of them left a run with part of its exceptions (a gateway of
    config.xml missing, its router isolated), so every part of a run is given this one reading."""
    try:
        with open(CONFIG, 'rb') as fh:
            if not take(fh, fcntl.LOCK_SH, wait):
                return None
            data = fh.read()
        return ET.fromstring(data)
    except (OSError, ET.ParseError):
        return None


def settings(root):
    """(on, hours) from config.xml's root - off where it says nothing: off by default."""
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


def gateways(root):
    """The gateways' addresses: config.xml's (the Gateways model, mounted at //OPNsense/Gateways), the
    routers OPNsense keeps for dynamic ones, and the default routes - a link-local one with its scope
    (neighbour_key()): the default route says it (fe80::1%igb1), and config.xml's gateway is on its
    interface's device."""
    out = set()
    for item in root.findall('OPNsense/Gateways/gateway_item') + root.findall('gateways/gateway_item'):
        key = neighbour_key(item.findtext('gateway'))
        name = (item.findtext('interface') or '').strip()
        if key and link_local(key) and '%' not in key and re.match(r'^\w+$', name):
            device = (root.findtext('interfaces/%s/if' % name) or '').strip()
            key += '%' + device if device else ''
        if key:
            out.add(key)
    try:
        names = [n for n in os.listdir(ROUTERS) if n.endswith('_router') or n.endswith('_routerv6')]
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(ROUTERS, name), encoding='utf-8', errors='replace') as fh:
                key = neighbour_key(fh.read().strip())
        except OSError:
            continue
        if key and link_local(key) and '%' not in key:
            key += '%' + name.rsplit('_router', 1)[0]       # the file is named for its device: igb2_routerv6
        if key:
            out.add(key)
    for family in ('-inet', '-inet6'):
        found = re.search(r'gateway:\s*(\S+)', run_cmd([ROUTE, '-n', 'get', family, 'default']))
        key = neighbour_key(found.group(1)) if found else ''
        if key:
            out.add(key)
    return out


def neighbour_key(addr):
    """An address as neighbours() keys it: a link-local one with its scope (fe80::1%igb0 and fe80::1%igb1
    are two neighbours), any other as norm_ip() gives it."""
    ip = norm_ip(addr)
    scope = str(addr or '').split('%')[1].split('/')[0].strip() if '%' in str(addr or '') else ''
    if ip and scope and ipaddress.ip_address(ip).is_link_local:
        return ip + '%' + scope
    return ip


def link_local(ip):
    """Whether an address - with a scope or without - is link-local: fe80::/10 or 169.254/16."""
    try:
        return ipaddress.ip_address(norm_ip(ip)).is_link_local
    except ValueError:
        return False


def macs_at(table, ip):
    """The MAC addresses neighbours() holds for an address, under any scope."""
    return sorted({mac for key, mac in table.items() if key.split('%')[0] == ip})


def macs_for(table, key):
    """The MAC addresses ARP and NDP show at an exception's address: a link-local one only under its own
    scope - fe80::1 on igb0 and on igb1 are two devices - and none for one without a scope, which could
    be any segment's."""
    ip = norm_ip(key)
    if not ip:
        return []
    if link_local(ip):
        key = neighbour_key(key)
        return [table[key]] if '%' in key and key in table else []
    return macs_at(table, ip)


def addresses_of(table, mac):
    """The addresses neighbours() holds for a MAC address, without their scopes."""
    return sorted({key.split('%')[0] for key, m in table.items() if m == mac})


def neighbours():
    """{address: MAC address} from the ARP and NDP tables now, link-local addresses with their scope."""
    out = {}
    for line in run_cmd([ARP, '-an']).splitlines():
        found = re.match(r'\S+ \(([^)]+)\) at (\S+)', line)
        if found and norm_ip(found.group(1)) and norm_mac(found.group(2)):
            out[norm_ip(found.group(1))] = norm_mac(found.group(2))
    for line in run_cmd([NDP, '-an']).splitlines():
        parts = line.split()
        if len(parts) >= 2 and norm_ip(parts[0]) and norm_mac(parts[1]):
            out[neighbour_key(parts[0])] = norm_mac(parts[1])
    return out


def ssh_logins():
    """The addresses logged in to this firewall's SSH now, as neighbour_key() gives them: utmpx's records of
    the users logged in, as who(1) prints them - "root  pts/0  Nov 17 10:00 (192.0.2.50)", the remote host
    last, in parentheses. sshd writes one for a session with a terminal. A host name (sshd's UseDNS) is not
    an address and is not taken."""
    out = set()
    for line in run_cmd([WHO]).splitlines():
        found = re.search(r'\(([^()\s]+)\)\s*$', line)
        key = neighbour_key(found.group(1)) if found else ''
        if key:
            out.add(key)
    return out


# OPNsense 26.7's web GUI at a login (authgui.inc:184-186): "<page>: Successful login for user '<name>' from:
# <address>"; the address is taken from the end, as a user name can hold anything
GUI_LOGIN = re.compile(r"Successful login for user '.*' from: (?P<address>[0-9A-Fa-f:.]+(?:%[\w.]+)?)\s*$")
STAMP = re.compile(r'^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)$')


def stamp(text):
    """An RFC 5424 time (2026-11-17T10:00:00.123+04:00) as Unix seconds; None for anything else."""
    found = STAMP.match(text or '')
    if not found:
        return None
    try:
        seconds = calendar.timegm(tuple(int(v) for v in found.groups()[:6]) + (0, 0, 0))
    except (ValueError, OverflowError):
        return None
    zone = found.group(7)
    if zone != 'Z':
        offset = int(zone[1:3]) * 3600 + int(zone[-2:]) * 60
        seconds -= offset if zone[0] == '+' else -offset
    return seconds


def audit_files(now, window):
    """The audit log's files that can hold a line of the last `window` seconds: one a day, named for its
    day - local time, or UTC."""
    days, t = set(), now - window
    while True:
        days.update(time.strftime('%Y%m%d', f(t)) for f in (time.localtime, time.gmtime))
        if t >= now:
            break
        t = min(t + 3600, now)
    return [AUDIT_LOG.format(day=day) for day in sorted(days)]


def tail(path, limit):
    """A file's lines, as bytes, from its last `limit` bytes - a first line that limit cut left out; []
    where it cannot be read."""
    try:
        with open(path, 'rb') as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - limit))
            lines = fh.read().split(b'\n')
    except OSError:
        return []
    return lines[1:] if size > limit else lines


def gui_logins(root, now):
    """The addresses logged in to this firewall's web GUI within its session timeout, as neighbour_key()
    gives them. OPNsense writes
    "Successful login for user '<name>' from: <address>" into its audit log at each login (authgui.inc:184-186,
    through auth_log(): the program "audit", auth.inc:37-42) - unless "Disable logging of web GUI successful
    logins" is set (system/webgui/quietlogin), when none is found here and only the page's client address
    counts. A session left unused for system/webgui/session_timeout minutes - 240 where empty - is ended
    (authgui.inc:219-236, ControllerRoot.php:131-160), so a login longer ago than that is not counted, nor
    one longer ago than MANAGER_DAYS. The log's lines are RFC 5424 ("<pri>1 time host program pid msgid sd
    message"); the newest AUDIT_READ bytes of a day's file are read."""
    try:
        minutes = float((root.findtext('system/webgui/session_timeout') or '').strip() or GUI_MINUTES)
    except ValueError:
        minutes = GUI_MINUTES
    window = int(min((minutes if minutes > 0 else GUI_MINUTES) * 60, MANAGER_DAYS * 86400))
    out = set()
    for path in audit_files(now, window):
        for raw in tail(path, AUDIT_READ):
            if b'Successful login for user' not in raw:
                continue
            parts = raw.decode('utf-8', 'replace').rstrip('\r').split(' ', 6)
            if len(parts) < 7 or not re.match(r'^<\d+>1$', parts[0]) or parts[3] != 'audit':
                continue
            at, found = stamp(parts[1]), GUI_LOGIN.search(parts[6])
            key = neighbour_key(found.group('address')) if found else ''
            if at is not None and -AHEAD <= now - at <= window and key:
                out.add(key)
    return out


def ha_peers(root):
    """The HA peer's addresses from config.xml's hasync (pfsync's peer, the configuration's target)."""
    out = set()
    for path in ('hasync/pfsyncpeerip', 'hasync/synchronizetoip', 'OPNsense/HASync/pfsyncpeerip',
                 'OPNsense/HASync/synchronizetoip'):
        text = (root.findtext(path) or '').strip()
        for word in re.split(r'[\s,]+', re.sub(r'^https?://', '', text)):
            ip = norm_ip(word.split(':')[0] if word.count(':') == 1 else word)
            if ip:
                out.add(ip)
    return out


def exceptions(root, state, now, table=None):
    """{'addr': {address: why}, 'mac': {mac: why}} - what is never isolated, each with its reason - from
    config.xml's root, STATE's page clients and ARP and NDP now (table, read here where not given)."""
    addr, mac = {}, {}
    table = neighbours() if table is None else table
    mine, my_macs = own()
    blind = not mine or not my_macs

    def add(keys, why):
        # each address, and the MAC addresses ARP and NDP show at it now (macs_for(): a link-local one
        # only under its scope); the first reason found stays an address's or a MAC address's
        for key in keys:
            if norm_ip(key):
                addr.setdefault(norm_ip(key), why)
            for m in macs_for(table, key):
                mac.setdefault(m, why)

    for m in my_macs:
        mac[m] = 'this firewall'
    # the firewall's own addresses too: the MAC address ARP shows at one that ifconfig does not list - a
    # CARP address's virtual one - is the firewall's
    add(mine, 'this firewall')
    add(gateways(root), 'a gateway')
    add(ha_peers(root), 'the HA peer')
    # a login, not a connection: a device scanning the GUI's or SSH's port opens one, and the
    # anti-lockout rule lets it. A link-local source counts for nothing here: fe80::1 is a neighbour of
    # every segment, and an isolated device keeps its own, which no table holds.
    add([key for key in ssh_logins() | gui_logins(root, now) if not link_local(key)],
        'logged in to the web GUI or SSH of this firewall')
    for ip, seen in (state.get('managers') or {}).items():
        if not isinstance(seen, dict) or now - number(seen.get('at')) > MANAGER_DAYS * 86400 or link_local(ip):
            continue
        add([ip], 'the address this page is opened from')
        if norm_mac(seen.get('mac')):
            mac.setdefault(norm_mac(seen.get('mac')), 'the address this page is opened from')
    return {'addr': addr, 'mac': mac, 'own_macs': set(my_macs), 'blind': blind, 'table': table}


def remember_client(state, client, now, table=None):
    """The address the page is opened from, with its MAC address now, kept as an exception - not a
    link-local one, which counts for nothing (exceptions()) - and the ones older than MANAGER_DAYS
    forgotten. Whether STATE changed."""
    managers = state.setdefault('managers', {})
    old = [k for k, v in managers.items()
           if not isinstance(v, dict) or now - number(v.get('at')) > MANAGER_DAYS * 86400]
    for k in old:
        del managers[k]
    ip = norm_ip(client)
    if not ip or link_local(ip):
        return bool(old)
    kept = managers.get(ip) if isinstance(managers.get(ip), dict) else {}
    managers[ip] = {'at': now, 'mac': (macs_at(neighbours() if table is None else table, ip) or [''])[0] or
                    norm_mac(kept.get('mac'))}
    return True


# ---------------------------------------------------------------- the list

def infected(state, table=None):
    """os-netreport's entries, each with its address in it and its device's MAC address ('mac') - the one
    os-netreport named kept as 'named'; {} where there is no file.

    An entry's device is the MAC address ARP or NDP shows at its address (table, read here where not
    given) where it shows one: os-netreport takes an address's MAC address from the newest holder in its
    own device scan and never clears it once set (alerts.py's device_of() and collect_c2()), so an address
    that moved before its scan saw the new holder is named for the device it had before - which was
    isolated, while the address that reached the list was not blocked. ARP and NDP are the kernel's view
    now, of a connection made in the last RECENT seconds. Where they show nothing, the MAC address
    os-netreport names; an entry with none, which ARP does not know either, has none (not isolated, and
    listed as such) and is looked up again at the next run. The device is found once for the entry's
    address and "last" and kept in STATE's macs, whichever way it was found: another device given that
    address later is not taken for it, and an entry ARP does not answer for in one run keeps its device.
    os-netreport's name of the entry is of the device it names, so it is not given to another."""
    data = load(INFECTED, {})
    out = {}
    found = state.setdefault('macs', {})
    for address, entry in data.items():
        ip = norm_ip(address)
        if not ip or not isinstance(entry, dict):
            continue
        named = norm_mac(entry.get('mac'))
        last = number(entry.get('last'))
        kept = found.get(ip) if isinstance(found.get(ip), dict) else {}
        if number(kept.get('last')) == last and norm_mac(kept.get('mac')):
            mac = norm_mac(kept.get('mac'))
        else:
            found.pop(ip, None)
            if table is None:
                table = neighbours()
            # a link-local address is every segment's: without a scope it names no one device
            holder = '' if link_local(ip) else (macs_at(table, ip) or [''])[0]
            mac = holder or named
            if mac:
                found[ip] = {'last': last, 'mac': mac}
        name = entry.get('name', '') if mac == named or not named else ''
        out[ip] = dict(entry, address=ip, mac=mac, named=named, name=name)
    for ip in [a for a in found if a not in out]:
        del found[ip]
    return out


def why_not(entry, exc):
    """Why this entry's device is not isolated, or None: its address or its MAC address an exception's.
    A MAC address ARP and NDP show at an exception's address is one already (exceptions()); a MAC address
    several devices share is isolated by its own addresses (shared())."""
    if entry['address'] in exc['addr']:
        return exc['addr'][entry['address']]
    if entry['mac'] in exc['mac']:
        return exc['mac'][entry['mac']]
    return None


def by_family(ips):
    """Addresses sorted IPv4 first."""
    return sorted(ips, key=lambda ip: (':' in ip, ip))


def shared(table, mac, exc):
    """Whether ARP shows a MAC address with more than one IPv4 address now: a repeater that puts its own
    MAC address on its clients' traffic, whose clients are as many devices. Only IPv4 tells: a device has
    one IPv4 address on a segment and many IPv6 ones. An exception's address is not counted: the gateway's
    or the page client's address under a device's MAC address says it answers ARP for another's, not
    that several devices are behind it."""
    return len([ip for ip in addresses_of(table, mac) if '.' in ip and ip not in exc.get('addr', {})]) > 1


def follow(item, mac, table, exc, now):
    """One run's look at an isolated MAC address (its item in STATE): every address ARP and NDP show for
    it now is remembered (item['seen'], with when), and held for the rest of its isolation (held()) - a
    device quiet for a while loses its ARP entry, and was let through when it spoke again until the next
    run. Not while it is shared: the first run ARP shows it with more than one IPv4 address marks it so
    for the rest of its isolation, and from then on it takes no new address - those are its clients'."""
    seen = item.get('seen') if isinstance(item.get('seen'), dict) else {}
    now_at = [ip for ip in addresses_of(table, mac) if not link_local(ip)]
    if not item.get('shared') and shared(table, mac, exc):
        item['shared'] = True
        log('isolate: %s shows more than one IPv4 address (%s): held by what reached the list and what it '
            'had alone, not by the addresses of its other clients' % (mac, ', '.join(ip for ip in now_at if '.' in ip)))
    if not item.get('shared'):
        for ip in now_at:
            if ip not in exc['addr']:
                seen[ip] = now
    item['seen'] = seen
    item['shared'] = bool(item.get('shared'))


def held(item, mac, table, exc):
    """The addresses held for one isolated MAC address: those that reached the list, those ARP and NDP
    show for it now (not for a shared one), and those it was seen with during its isolation, newest
    first - never a link-local one (a table has no scope), an exception's (a device answering ARP for a
    gateway's address does not have it put into the table), or one ARP or NDP shows under another MAC
    address now: another device has it by then."""
    ranked = by_family(listed(item.get('addresses')))
    if not item.get('shared'):
        ranked += by_family(addresses_of(table, mac))
    seen = item.get('seen') if isinstance(item.get('seen'), dict) else {}
    ranked += [ip for ip, _ in sorted(seen.items(), key=lambda kv: (-number(kv[1]), str(kv[0])))]
    out = []
    for ip in (norm_ip(a) for a in ranked):
        if not ip or ip in out or link_local(ip) or ip in exc.get('addr', {}):
            continue
        if any(m != mac for m in macs_at(table, ip)):
            continue
        out.append(ip)
    return out


def held_back(record, now):
    """(the "last" an undone or expired device is let go against, the time before which it is not
    isolated again) from STATE's released - a number in an older STATE."""
    if isinstance(record, dict):
        return number(record.get('last')), number(record.get('until'))
    return number(record if record is not None else -1), 0


def released_last(entries, mac):
    """The newest "last" among os-netreport's entries of this MAC address: an undone or expired device
    is isolated again only for a newer one."""
    return max([number(e.get('last')) for e in entries.values() if e['mac'] == mac] or [0])


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
    table = exc.get('table') or {}
    for mac, item in list(isolated.items()):
        why = None
        # never longer than the duration from now: a shorter one set, or the clock stepped back
        item['until'] = min(number(item.get('until')), now + hours * 3600)
        if now >= item['until']:
            why = 'expired'
        elif mac in exc.get('own_macs', ()):
            why = 'this firewall'
        # and for nothing else: an exception's address it answers ARP for, an address it takes - it made
        # its MAC address "shared" with a second IPv4 one - or a connection it opened would have let it go.
        # Such an address is kept out of the table instead (held()).
        if why:
            released[mac] = {'last': max(released_last(entries, mac), number(item.get('last'))), 'until': 0,
                             'addresses': listed(item.get('addresses'))}
            gone.append(mac)
            del isolated[mac]
        else:
            follow(item, mac, table, exc, now)
    skipped = {}
    added = []
    if exc.get('blind'):
        # the firewall's own addresses could not be read: it could isolate itself - nothing new this run
        state['skipped'] = skipped
        return added, gone
    for entry in sorted(entries.values(), key=lambda e: e['address']):
        last = number(entry.get('last'))
        if not entry['mac']:
            continue                    # listed by the page from infected.json: not isolated, no MAC
        if now - last > RECENT or last - now > AHEAD:
            continue
        reason = why_not(entry, exc)
        if reason:
            skipped[entry['address']] = {'mac': entry['mac'], 'reason': reason, 'last': last,
                                         'list': entry.get('list', ''), 'name': entry.get('name', '')}
            continue
        mac = entry['mac']
        if mac in isolated:
            item = isolated[mac]
            if entry['address'] not in listed(item.get('addresses')):
                item['addresses'] = sorted(set(listed(item.get('addresses'))) | {entry['address']})
            item['last'] = max(number(item.get('last')), last)
            continue
        let_go_last, let_go_until = held_back(released.get(mac), now)
        if mac in released and (now < let_go_until or last <= let_go_last):
            skipped[entry['address']] = {'mac': mac, 'reason': 'undone', 'last': last,
                                         'list': entry.get('list', ''), 'name': entry.get('name', '')}
            continue
        # a MAC address ARP shows with more than one IPv4 address now is isolated too, by its own
        # addresses only: follow() finds it shared from the start, and it takes none of its clients'
        isolated[mac] = {'addresses': [entry['address']], 'list': entry.get('list', ''),
                         'name': entry.get('name', ''), 'since': now, 'until': now + hours * 3600,
                         'last': last, 'seen': {}, 'shared': False}
        if entry.get('named') and entry['named'] != mac:
            log('isolate: %s: os-netreport names %s, but ARP or NDP showed %s at that address - %s isolated'
                % (entry['address'], entry['named'], mac, mac))
        follow(isolated[mac], mac, table, exc, now)
        released.pop(mac, None)
        added.append(mac)
    # a let-go device is remembered while it is held back, or os-netreport keeps an entry of its MAC
    # address or of one of its addresses
    for mac in list(released):
        record = released[mac]
        addresses = listed(record.get('addresses')) if isinstance(record, dict) else []
        if now < held_back(record, now)[1]:
            continue
        if not any(e['mac'] == mac or e['address'] in addresses for e in entries.values()):
            del released[mac]
    state['skipped'] = skipped
    return added, gone


ALIAS_NOT_READY = {
    'missing': 'the alias %s is not there: Apply on the Settings tab makes it' % ALIAS,
    'off': 'the alias %s is switched off: Apply on the Settings tab switches it on' % ALIAS,
    # a MAC alias of that name - an earlier build's, or the owner's - is OPNsense's to fill from ARP and
    # NDP, so what is emptied here would come back: said, until Apply makes it the external one
    'not external': 'the alias %s is not an external alias: Apply on the Settings tab makes it one' % ALIAS,
}


def alias_state(root):
    """Whether the isolated devices' alias is there to be filled - 'ready': in config.xml, on and
    external, as apply.php makes it at the page's Apply while automatic isolation is on - or why not:
    'missing', 'off', 'not external' (ALIAS_NOT_READY)."""
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        if alias.findtext('name') == ALIAS:
            if (alias.findtext('enabled') or '1') != '1':
                return 'off'
            return 'ready' if (alias.findtext('type') or '') == 'external' else 'not external'
    return 'missing'


def table_now():
    """The addresses pf's isolated devices' table holds now, sorted; None where there is no such table."""
    try:
        r = subprocess.run([PFCTL, '-t', ALIAS, '-T', 'show'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return sorted({norm_ip(line) for line in r.stdout.splitlines() if norm_ip(line)})


def blocked_addresses(state, exc):
    """What the table is to hold: every isolated device's held() addresses - each device's kept in STATE
    (its 'held'), for the page to say whether pf holds them."""
    table = exc.get('table')
    if table is None:
        table = neighbours()
    out = set()
    for mac, item in (state.get('isolated') or {}).items():
        if isinstance(item, dict):
            item['held'] = held(item, mac, table, exc)
            out.update(item['held'])
    return sorted(out)


def fill_table(want):
    """pf's table made to hold these addresses, and the open connections of those it gains cut (cut.py,
    as the page's Apply runs it). The firewall's part of the summary."""
    have = table_now()
    if have is None and not want:
        # nothing to hold, and no table (a filter reload that failed, say): nothing to do, no failure to
        # write into the system log every minute
        return {'status': 'ok', 'held': 0}
    if have is None:
        return {'status': 'failed', 'errors': ['no table %s: Apply on the Settings tab makes it' % ALIAS]}
    if have == want:
        return {'status': 'ok', 'held': len(have)}
    args = [PFCTL, '-t', ALIAS, '-T', 'replace'] + want if want else [PFCTL, '-t', ALIAS, '-T', 'flush']
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return {'status': 'failed', 'errors': [str(e)]}
    if r.returncode != 0:
        return {'status': 'failed', 'errors': [(r.stderr or r.stdout).strip()[:200] or 'pfctl failed']}
    answer = {'status': 'ok', 'held': len(want), 'added': sorted(set(want) - set(have)),
              'removed': sorted(set(have) - set(want))}
    if answer['added']:
        out = run_cmd([CUT], timeout=120).strip()
        try:
            answer['cut'] = json.loads(out.splitlines()[-1]) if out else None
        except ValueError:
            answer['cut'] = None
    return answer


def commit(state, added, gone, summary, exc, alias):
    """STATE written, and pf's table made to hold the addresses the isolated devices have now - at every
    run, as addresses move (a lease renewed), and so that a STATE that was lost empties it. exc is this
    run's exceptions, whose addresses the table never holds, and alias the alias's state (alias_state()):
    Undo is given both as a run is."""
    want = blocked_addresses(state, exc) if state.get('isolated') else []
    if alias == 'ready' or (not want and table_now()):
        # nothing to hold and the table still holding addresses (isolation turned off, its alias gone or
        # switched off): emptied all the same - nobody stays isolated with nothing on the page
        answer = fill_table(want)
    else:
        answer = {'status': 'ok', 'held': 0}
    if alias != 'ready' and (want or alias == 'not external'):
        answer = {'status': 'failed', 'errors': [ALIAS_NOT_READY.get(alias, ALIAS_NOT_READY['missing'])]}
    summary['firewall'] = answer
    if answer.get('status') != 'ok':
        log('isolation list not put into the firewall: %s' % '; '.join(answer.get('errors') or ['failed']))
    for mac in added:
        item = state['isolated'][mac]
        log('isolated %s (%s): reached %s, until %s%s' % (mac, ', '.join(item['addresses']), item.get('list') or '?',
            time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(item['until'])),
            '; a MAC address several devices share: only its own addresses held' if item.get('shared') else ''))
    for mac in gone:
        log('isolation of %s ended' % mac)
    save(STATE, state)


NOT_READ = 'isolate: config.xml could not be read; nothing changed'


def do_run(now=None):
    now = int(now if now is not None else time.time())
    root = read_config()
    if root is None:
        # nothing isolated, let go or written on a part of the exceptions; the next minute reads it again
        log(NOT_READ)
        return {'run': now, 'status': 'failed', 'message': NOT_READ}
    on, hours = settings(root)
    state = load(STATE, {})
    summary = {'run': now, 'on': bool(on)}
    # off, nothing isolated and nothing in the table: once a minute, nothing to write
    if not on and not state.get('isolated') and not state.get('released') and not table_now():
        summary['message'] = 'isolate: off'
        return summary
    # one reading of ARP and NDP for the whole run: the entries' devices and the exceptions' MAC addresses
    table = neighbours() if on else {}
    entries = infected(state, table) if on else {}
    exc = exceptions(root, state, now, table) if on else {'addr': {}, 'mac': {}}
    added, gone = step(state, entries, exc, on, hours, now)
    summary.update({'isolated': sorted(state['isolated']), 'added': added, 'let_go': gone})
    commit(state, added, gone, summary, exc, alias_state(root))
    if exc.get('blind'):
        log('isolate: this firewall\'s own addresses could not be read (ifconfig): nothing new isolated')
        summary['message'] = 'isolate: this firewall\'s own addresses could not be read; nothing new isolated'
    summary.setdefault('message', 'isolate: %d isolated, %d new, %d let go' % (len(state['isolated']), len(added),
                                                                            len(gone)))
    return summary


def do_list(client, now=None):
    now = int(now if now is not None else time.time())
    root = read_config()
    if root is None:
        # said as a failure, which the page shows as such - not as "off" and an empty list
        return {'status': 'failed', 'message': NOT_READ}
    on, hours = settings(root)
    state = load(STATE, {})
    table = neighbours()
    if remember_client(state, client, now, table):
        save(STATE, state)
    rows = []
    # what pf holds, against what the last run asked it to hold for each device (its 'held'): a row the
    # table does not hold is said - one with nothing to hold too - and one ARP and NDP show no address of
    # now (addresses_now) is said, not drawn as held
    in_table = set(table_now() or [])
    for mac, item in sorted((state.get('isolated') or {}).items()):
        now_at = [ip for ip in addresses_of(table, mac) if not link_local(ip)]
        holding = [ip for ip in listed(item.get('held')) if norm_ip(ip)]
        rows.append({'mac': mac, 'addresses': listed(item.get('addresses')), 'list': item.get('list', ''),
                     'name': item.get('name', ''), 'since': item.get('since'), 'until': item.get('until'),
                     'holding': holding, 'addresses_now': now_at, 'shared': bool(item.get('shared')),
                     'held': bool(holding) and all(ip in in_table for ip in holding)})
    entries = infected(state, table)
    others = [{'address': ip, 'mac': '', 'name': e.get('name', ''), 'list': e.get('list', ''),
               'last': e.get('last'), 'reason': 'no MAC'} for ip, e in sorted(entries.items()) if not e['mac']]
    for ip, item in sorted((state.get('skipped') or {}).items()):
        if ip in entries:
            others.append(dict(item, address=ip))
    return {'on': bool(on), 'hours': hours, 'isolated': rows, 'not_isolated': others}


def do_undo(mac, client, now=None):
    now = int(now if now is not None else time.time())
    mac = norm_mac(mac)
    root = read_config()
    if root is None:
        return {'status': 'failed', 'message': NOT_READ}
    state = load(STATE, {})
    table = neighbours()
    remember_client(state, client, now, table)
    item = (state.get('isolated') or {}).pop(mac, None) if mac else None
    if item is None:
        save(STATE, state)
        return {'status': 'failed', 'message': 'not isolated: %s' % (mac or 'no MAC address given')}
    # held back until the isolation would have ended: a device taken for infected by mistake keeps reaching
    # the list, and would be isolated again the next minute
    state.setdefault('released', {})[mac] = {'last': max(released_last(infected(state, table), mac),
                                                         number(item.get('last'))),
                                             'until': number(item.get('until')),
                                             'addresses': listed(item.get('addresses'))}
    summary = {'status': 'ok', 'mac': mac}
    # the table written as a run writes it: never an exception's address - another isolated device may
    # answer ARP for a gateway's by now - and only while the alias is ready
    commit(state, [], [mac], summary, exceptions(root, state, now, table), alias_state(root))
    if (summary.get('firewall') or {}).get('status') != 'ok':
        summary['status'] = 'failed'
    return summary


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
