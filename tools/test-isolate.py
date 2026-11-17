#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""Automatic isolation against files in a temporary directory, no OPNsense:

  * isolate.py - off by default and with the option off; an entry of os-netreport's infected.json
    with a MAC address and a "last" in the last 10 minutes isolated by its MAC address until the
    duration, an older one not, one without a MAC address listed as not isolated; never the
    firewall's own addresses and MAC addresses, its gateways' (config.xml, /tmp's router files, the
    default route) and their MAC addresses, or an address the page was opened from; undo at once,
    and not again for the same entry until a newer "last"; expiry; the option turned off letting
    every device go; the alias made from the list, so a lost list empties it;
  * cut.py - the isolated devices' table watched with automatic isolation on, its new addresses'
    states killed by id, its own snapshot, and the blocked devices' table as before;
  * plugins.inc.d/portguard.inc - the isolated devices' rules registered while automatic isolation is
    on and its alias there, whether or not the blocked devices are (with php, where it is installed).

The commands they call (ifconfig, arp, ndp, route, pfctl, cut.py) are small scripts here that print
what a firewall would; pfctl keeps the isolated devices' table in a file. POSIX only (fcntl, sh): run it on Linux or FreeBSD, or under WSL.

    python3 tools/test-isolate.py"""
import fcntl
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'portguard')
failures = 0


def check(name, got, want):
    global failures
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


if os.name != 'posix':
    print('FAIL this test needs POSIX (fcntl, sh): run it on Linux or FreeBSD, or under WSL')
    sys.exit(1)

TOP = tempfile.mkdtemp(prefix='os-portguard-test-')
BIN = os.path.join(TOP, 'bin')
FIX = os.path.join(TOP, 'fixtures')
ROUTERS = os.path.join(TOP, 'tmp')
for d in (BIN, FIX, ROUTERS):
    os.makedirs(d)
CONFIG = os.path.join(TOP, 'config.xml')
INFECTED = os.path.join(TOP, 'infected.json')
NOW = 1763337600

FW_MAC, GW_MAC, PC_MAC, BAD_MAC, BAD2_MAC, ADMIN_MAC = (
    '02:00:00:00:00:01', '02:00:00:00:00:fe', '02:00:00:00:10:01', '02:00:00:00:66:01',
    '02:00:00:00:66:02', '02:00:00:00:aa:01')


def tool(name, body):
    path = os.path.join(BIN, name)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('#!/bin/sh\n' + body + '\n')
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def fixture(name, text):
    with open(os.path.join(FIX, name), 'w', encoding='utf-8') as fh:
        fh.write(text)


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture('ifconfig', 'igb0: flags=8843<UP> mtu 1500\n\tether %s\n\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255\n'
        '\tinet6 fe80::1%%igb0 prefixlen 64 scopeid 0x1\n\tinet6 2001:db8::1 prefixlen 64\n'
        'igb1: flags=8843<UP> mtu 1500\n\tether 02:00:00:00:00:02\n\tinet 203.0.113.2 netmask 0xffffff00\n' % FW_MAC)
fixture('arp', '? (203.0.113.1) at %s on igb1 expires in 1200 seconds [ethernet]\n'
        '? (192.0.2.10) at %s on igb0 expires in 1100 seconds [ethernet]\n'
        '? (192.0.2.50) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.77) at (incomplete) on igb0 expired [ethernet]\n' % (GW_MAC, PC_MAC, ADMIN_MAC))
fixture('ndp', 'Neighbor                             Linklayer Address  Netif Expire    1s 5s\n'
        '2001:db8::66                         %s  igb0 23h59m58s S R\n' % BAD_MAC)
fixture('route-inet', '   route to: default\ndestination: default\n    gateway: 203.0.113.1\n  interface: igb1\n')
fixture('route-inet6', 'route: route has not been found\n')
tool('ifconfig', 'cat "%s/ifconfig"' % FIX)
tool('arp', 'cat "%s/arp"' % FIX)
tool('ndp', 'cat "%s/ndp"' % FIX)
tool('route', 'case "$*" in *-inet6*) cat "%s/route-inet6" ;; *) cat "%s/route-inet" ;; esac' % (FIX, FIX))
# who(1): the users logged in, utmpx's records (none here until a test says); the audit log, a file a day
fixture('who', '')
tool('who', 'cat "%s/who"' % FIX)
AUDIT = os.path.join(TOP, 'audit')
os.makedirs(AUDIT)
with open(os.path.join(ROUTERS, 'igb2_routerv6'), 'w', encoding='utf-8') as fh:
    fh.write('2001:db8:ffff::1\n')
with open(os.path.join(ROUTERS, 'igb0_nameserver'), 'w', encoding='utf-8') as fh:
    fh.write('198.51.100.200\n')

# pfctl stands in for the isolated devices' table: a file holds what it holds, every replace or flush is recorded
# (WRITES, the addresses as a JSON list a line), and so is every call's command line (CALLS); a replace takes its
# addresses from the command line and from the file -f names, "-" its stdin, as pfctl does. It lists no state.
# cut.py stands in, counting its runs
TABLE = os.path.join(TOP, 'table-portguard_isolated')
WRITES = os.path.join(TOP, 'writes.jsonl')
CALLS = os.path.join(TOP, 'pfctl-calls.jsonl')
CUTS = os.path.join(TOP, 'cuts')
pf = os.path.join(TOP, 'pfctl-table.py')
with open(pf, 'w', encoding='utf-8') as fh:
    fh.write('''import json, os, sys
table, writes, args = sys.argv[1], sys.argv[2], sys.argv[3:]
if args[:1] == ['-ss']:
    # pf's states, which isolate.py no longer reads: a half-open one to the firewall's SSH is no login
    states = os.path.join(os.path.dirname(table), 'fixtures', 'states-pf')
    sys.stdout.write(open(states).read() if os.path.exists(states) else '')
    sys.exit(0)
if args[:2] != ['-t', 'portguard_isolated'] or not os.path.exists(table):
    sys.stderr.write('pfctl: Table does not exist.\\n')
    sys.exit(1)
op = args[3] if len(args) > 3 else ''
with open(os.path.join(os.path.dirname(table), 'pfctl-calls.jsonl'), 'a') as f:
    f.write(json.dumps(args) + '\\n')
if op == 'show':
    sys.stdout.write(open(table).read())
elif op in ('replace', 'flush'):
    addrs = args[4:]
    if args[4:6] == ['-f', '-']:
        addrs = args[6:] + sys.stdin.read().split()
    addrs = sorted(addrs) if op == 'replace' else []
    open(table, 'w').write(''.join('   %s\\n' % a for a in addrs))
    with open(writes, 'a') as f:
        f.write(json.dumps(addrs) + '\\n')
''')
tool('pfctl-table', '"%s" "%s" "%s" "%s" "$@"' % (sys.executable, pf, TABLE, WRITES))
open(TABLE, 'w').close()           # the table there, as the filter makes it for the external alias
tool('cut-standin', 'echo run >> "%s"; echo \'{"status": "ok"}\'' % CUTS)
ISOLATED_ALIAS = '<alias><name>portguard_isolated</name><enabled>1</enabled><type>external</type><content/></alias>'


def config(auto=None, hours=None, enabled='1', aliases=''):
    """config.xml; with automatic isolation on, the external alias apply.php makes for it at Apply."""
    if auto == '1' and 'portguard_isolated' not in aliases:
        aliases += ISOLATED_ALIAS
    general = '<enabled>%s</enabled><log>0</log>' % enabled
    if auto is not None:
        general += '<auto_isolate>%s</auto_isolate>' % auto
    if hours is not None:
        general += '<isolate_hours>%s</isolate_hours>' % hours
    with open(CONFIG, 'w', encoding='utf-8') as fh:
        fh.write('<?xml version="1.0"?>\n<opnsense><OPNsense><PortGuard version="1.0.0"><general>%s</general>'
                 '<devices/></PortGuard><Gateways><gateway_item><name>WAN_GW</name><gateway>203.0.113.1</gateway>'
                 '</gateway_item><gateway_item><name>LAN6</name><gateway>dynamic</gateway></gateway_item></Gateways>'
                 '<Firewall><Alias><aliases>%s</aliases></Alias></Firewall></OPNsense></opnsense>\n' % (general, aliases))


def infected(entries):
    with open(INFECTED, 'w', encoding='utf-8') as fh:
        json.dump(entries, fh)


def entry(last, mac='', lst='feodo', name=''):
    return {'first': last - 100, 'last': last, 'count': 3, 'list': lst, 'mac': mac, 'name': name}


def writes():
    try:
        with open(WRITES, encoding='utf-8') as fh:
            return [json.loads(line) for line in fh]
    except OSError:
        return []


iso = load('isolate')
iso.CONFIG, iso.INFECTED, iso.ROUTERS = CONFIG, INFECTED, ROUTERS
iso.STATE_DIR = os.path.join(TOP, 'db')
iso.STATE = os.path.join(iso.STATE_DIR, 'isolate.json')
iso.LOCK = os.path.join(iso.STATE_DIR, 'isolate.lock')
iso.IFCONFIG, iso.ARP, iso.NDP, iso.ROUTE = (os.path.join(BIN, n) for n in ('ifconfig', 'arp', 'ndp', 'route'))
iso.PFCTL, iso.CUT = os.path.join(BIN, 'pfctl-table'), os.path.join(BIN, 'cut-standin')
iso.WHO, iso.AUDIT_LOG = os.path.join(BIN, 'who'), os.path.join(AUDIT, 'audit_{day}.log')
logged = []
iso.log = logged.append
os.makedirs(iso.STATE_DIR)


def state():
    return iso.load(iso.STATE, {})


# ---------------------------------------------------------------- the commands, read

mine, my_macs = iso.own()
check('own addresses from ifconfig', sorted(mine), ['192.0.2.1', '2001:db8::1', '203.0.113.2', 'fe80::1'])
check('own MAC addresses from ifconfig', sorted(my_macs), [FW_MAC, '02:00:00:00:00:02'])
config()
check('gateways: config.xml, /tmp router files, the default route', sorted(iso.gateways(iso.read_config())),
      ['2001:db8:ffff::1', '203.0.113.1'])
check('neighbours from ARP and NDP, incomplete ones left out', iso.neighbours(),
      {'203.0.113.1': GW_MAC, '192.0.2.10': PC_MAC, '192.0.2.50': ADMIN_MAC, '2001:db8::66': BAD_MAC})

# ---------------------------------------------------------------- off by default

infected({'192.0.2.66': entry(NOW - 60, BAD_MAC)})
config()
check('settings: off by default, 24 hours', iso.settings(iso.read_config()), (False, 24))
check('off by default: nothing isolated', iso.do_run(NOW).get('message'), 'isolate: off')
check('off by default: no state written, no alias', (os.path.exists(iso.STATE), writes()), (False, []))
config(auto='0')
check('off: nothing isolated', iso.do_run(NOW).get('message'), 'isolate: off')

# ---------------------------------------------------------------- isolating

config(auto='1', hours='2')
check('settings: on, 2 hours', iso.settings(iso.read_config()), (True, 2))
infected({
    '192.0.2.66': entry(NOW - 60, BAD_MAC, name='camera'),          # recent, MAC known: isolated
    '2001:db8::66': entry(NOW - 30, BAD_MAC),                       # the same device's IPv6 address
    '192.0.2.67': entry(NOW - 3600, BAD2_MAC),                      # an hour ago: not acted on
    '192.0.2.68': entry(NOW - 10),                                  # no MAC: listed, not isolated
    '192.0.2.1': entry(NOW - 10, '02:00:00:00:00:99'),              # the firewall's own address
    '192.0.2.70': entry(NOW - 10, FW_MAC),                          # the firewall's MAC
    '203.0.113.1': entry(NOW - 10, GW_MAC),                         # the gateway
    '192.0.2.71': entry(NOW - 10, GW_MAC),                          # the gateway's MAC at another address
})
answer = iso.do_run(NOW)
check('a recent entry with its MAC: isolated by MAC', answer.get('added'), [BAD_MAC])
item = state()['isolated'][BAD_MAC]
check('isolated: both its addresses, its list, its name', (item['addresses'], item['list'], item['name']),
      (['192.0.2.66', '2001:db8::66'], 'feodo', 'camera'))
check('isolated: until now + the duration', (item['since'], item['until']), (NOW, NOW + 2 * 3600))
check('the table made to hold the isolated MAC address\'s addresses - those that reached the list, the one NDP '
      'shows now - not the others\'', writes(), [['192.0.2.66', '2001:db8::66']])
check('... and the cut run for what it gained', open(CUTS).read().split(), ['run'])
check('an entry an hour old: not isolated', BAD2_MAC in state()['isolated'], False)
skipped = state()['skipped']
check('the firewall, its MAC, the gateway and its MAC: not isolated, each with why',
      {a: skipped[a]['reason'] for a in skipped},
      {'192.0.2.1': 'this firewall', '192.0.2.70': 'this firewall', '203.0.113.1': 'a gateway',
       '192.0.2.71': 'a gateway'})
check('the system log says what was isolated', any(line.startswith('isolated ' + BAD_MAC) for line in logged), True)

listing = iso.do_list('192.0.2.50', NOW)
check('list: on, the duration, the isolated device', (listing['on'], listing['hours'],
      [r['mac'] for r in listing['isolated']]), (True, 2, [BAD_MAC]))
reasons = {r['address']: r['reason'] for r in listing['not_isolated']}
check('list: no MAC listed as such, and the exceptions', reasons,
      {'192.0.2.68': 'no MAC', '192.0.2.1': 'this firewall', '192.0.2.70': 'this firewall',
       '203.0.113.1': 'a gateway', '192.0.2.71': 'a gateway'})
check('list: the page client kept with its MAC', state()['managers']['192.0.2.50'], {'at': NOW, 'mac': ADMIN_MAC})

check('a second run, nothing new: the table not written again', (iso.do_run(NOW + 60).get('added'), len(writes())),
      ([], 1))

# an entry written without a MAC address takes the one ARP holds for its address; one ARP does not know stays empty
kept = iso.load(iso.INFECTED, {})
infected({'192.0.2.10': entry(NOW - 10), '192.0.2.68': entry(NOW - 10)})
found = iso.infected({})
check('no MAC in the entry: the ARP table\'s MAC for its address', (found['192.0.2.10']['mac'],
      found['192.0.2.68']['mac']), (PC_MAC, ''))
# ... found once for the entry's address and "last", and kept: another device given that address later is not taken
# for it, a run ARP does not answer in keeps it; a newer "last" is looked up again
with open(os.path.join(FIX, 'arp'), encoding='utf-8') as fh:
    ARP_TEXT = fh.read()
OTHER_MAC = '02:00:00:00:10:02'
macs_state = {}
infected({'192.0.2.10': entry(NOW - 10)})
seen = [iso.infected(macs_state)['192.0.2.10']['mac']]
fixture('arp', ARP_TEXT.replace(PC_MAC, OTHER_MAC))
seen.append(iso.infected(macs_state)['192.0.2.10']['mac'])
fixture('arp', ''.join(line for line in ARP_TEXT.splitlines(True) if '(192.0.2.10)' not in line))
seen.append(iso.infected(macs_state)['192.0.2.10']['mac'])
infected({'192.0.2.10': entry(NOW + 50)})
fixture('arp', ARP_TEXT.replace(PC_MAC, OTHER_MAC))
seen.append(iso.infected(macs_state)['192.0.2.10']['mac'])
fixture('arp', ARP_TEXT)
check('the MAC found for an entry kept while its "last" is the same: not another holder of the address, not lost '
      'when ARP misses once; a newer "last" looked up again', seen, [PC_MAC, PC_MAC, PC_MAC, OTHER_MAC])
infected({})
check('... and forgotten once the entry is gone', (iso.infected(macs_state), macs_state['macs']), ({}, {}))
iso.save(iso.INFECTED, kept)

# ---------------------------------------------------------------- the page's client, never

infected({'192.0.2.50': entry(NOW + 100, ADMIN_MAC), '192.0.2.51': entry(NOW + 100, ADMIN_MAC),
          '192.0.2.66': entry(NOW - 60, BAD_MAC)})
iso.do_run(NOW + 120)
check('the address the page was opened from, and its MAC elsewhere: not isolated',
      (ADMIN_MAC in state()['isolated'], state()['skipped']['192.0.2.50']['reason'],
       state()['skipped']['192.0.2.51']['reason']),
      (False, 'the address this page is opened from', 'the address this page is opened from'))
st = state()
st['managers']['192.0.2.50']['at'] = NOW - 8 * 86400
iso.save(iso.STATE, st)
iso.do_run(NOW + 130)
check('an address the page was opened from 8 days ago is no longer an exception', ADMIN_MAC in state()['isolated'], True)
iso.do_undo(ADMIN_MAC, '', NOW + 131)

# ---------------------------------------------------------------- undo

infected({'192.0.2.66': entry(NOW - 60, BAD_MAC), '2001:db8::66': entry(NOW - 30, BAD_MAC)})
n = len(writes())
answer = iso.do_undo(BAD_MAC, '192.0.2.50', NOW + 200)
check('undo: ok, let go at once, the table emptied of it',
      (answer.get('status'), BAD_MAC in state()['isolated'], writes()[n:]), ('ok', False, [[]]))
check('undo: held back against the newest "last" of its entries, until its isolation would have ended',
      (state()['released'][BAD_MAC]['last'], state()['released'][BAD_MAC]['until']), (NOW - 30, NOW + 2 * 3600))
iso.do_run(NOW + 260)
check('undone: not isolated again for the same entry', (BAD_MAC in state()['isolated'],
      state()['skipped']['2001:db8::66']['reason']), (False, 'undone'))
# a device taken for infected by mistake keeps reaching the list: Undo holds until its isolation would have ended
infected({'192.0.2.66': entry(NOW + 300, BAD_MAC), '2001:db8::66': entry(NOW - 30, BAD_MAC)})
iso.do_run(NOW + 320)
check('undone: a newer "last" before its isolation would have ended - still let through',
      (BAD_MAC in state()['isolated'], state()['skipped']['192.0.2.66']['reason']), (False, 'undone'))
infected({'192.0.2.66': entry(NOW + 2 * 3600 + 5, BAD_MAC), '2001:db8::66': entry(NOW - 30, BAD_MAC)})
iso.do_run(NOW + 2 * 3600 + 10)
check('undone: a newer "last" after that: isolated again', BAD_MAC in state()['isolated'], True)
check('undo of a device not isolated: failed, nothing written',
      iso.do_undo(BAD2_MAC, '', NOW + 330).get('status'), 'failed')

# ---------------------------------------------------------------- expiry, and off

until = state()['isolated'][BAD_MAC]['until']
iso.do_run(until)
check('expired: let go, and not again for the same entry', (BAD_MAC in state()['isolated'],
      state()['released'][BAD_MAC]['last'], state()['released'][BAD_MAC]['until']), (False, NOW + 2 * 3600 + 5, 0))
infected({'192.0.2.66': entry(until + 10, BAD_MAC)})
iso.do_run(until + 20)
check('a newer connection after expiry: isolated again', BAD_MAC in state()['isolated'], True)
config(auto='0')
n = len(writes())
answer = iso.do_run(until + 30)
check('turned off (the alias gone at Apply): every device let go, the table emptied all the same', (state()['isolated'], answer.get('let_go'), writes()[n:]),
      ({}, [BAD_MAC], [[]]))
check('off again, nothing left: nothing written', (iso.do_run(until + 90).get('message'), len(writes())),
      ('isolate: off', n + 1))

# ---------------------------------------------------------------- the list lost

config(auto='1')
with open(TABLE, 'w', encoding='utf-8') as fh:
    fh.write('   192.0.2.67\n')
os.remove(iso.STATE)
infected({})
n = len(writes())
iso.do_run(until + 100)
check('the list lost (a /var in memory, a reboot): the table emptied', writes()[n:], [[]])
# no table (the alias not made: Apply not pressed) while a device is to be isolated: said, nothing written
os.remove(TABLE)
infected({'192.0.2.66': entry(until + 100, BAD_MAC)})
answer = iso.do_run(until + 110)
check('no table to fill: isolated in the list, the firewall part failed with why',
      (BAD_MAC in state()['isolated'], answer['firewall']['status'], answer['firewall']['errors']),
      (True, 'failed', ['no table portguard_isolated: Apply on the Settings tab makes it']))
listing = iso.do_list('', until + 120)
check('the list says the firewall does not hold its addresses', [d['held'] for d in listing['isolated']], [False])
open(TABLE, 'w').close()
iso.do_run(until + 130)
listing = iso.do_list('', until + 140)
check('... and that it does once the table is there and filled', ([d['held'] for d in listing['isolated']],
      [d['addresses_now'] for d in listing['isolated']]), ([True], [['2001:db8::66']]))
iso.do_undo(BAD_MAC, '', until + 150)
os.remove(iso.STATE)
infected({})
config(auto='1', hours='99999')
check('a duration out of range is held to 720 hours', iso.settings(iso.read_config()), (True, 720))
config(auto='1', hours='x')
check('a duration that is not a number: 24 hours', iso.settings(iso.read_config()), (True, 24))
check('main: unknown command answers in JSON', subprocess.run(
    [sys.executable, '-c', 'import sys; sys.path.insert(0, %r); import isolate; isolate.STATE_DIR = %r; '
     'isolate.LOCK = %r; isolate.main(["nonsense"])' % (SCRIPTS, iso.STATE_DIR, iso.LOCK)],
    capture_output=True, text=True).stdout.strip().startswith('{"message": "usage'), True)

# ---------------------------------------------------------------- the review's small findings (2026-11-17)

config(auto='1', hours='2')
if os.path.exists(iso.STATE):
    os.remove(iso.STATE)
infected({'192.0.2.66': entry(NOW, BAD_MAC)})
iso.do_run(NOW + 10)
# a "last" os-netreport's file holds as a date: neither the run nor Undo stops
infected({'192.0.2.66': dict(entry(NOW, BAD_MAC), last='2026-11-17T10:00:00Z')})
answer = iso.do_run(NOW + 20)
check('a "last" written as a date: the run goes on, the device stays isolated',
      ('stopped' in (answer.get('message') or ''), BAD_MAC in state()['isolated']), (False, True))
check('... and Undo goes through', iso.do_undo(BAD_MAC, '', NOW + 30).get('status'), 'ok')
check('a broadcast, a multicast or a zero MAC address is no one device\'s',
      [iso.norm_mac(m) for m in ('ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:01', '00:00:00:00:00:00', BAD_MAC)],
      ['', '', '', BAD_MAC])
check('an IPv4 address an IPv6 one carries is read as IPv4', iso.norm_ip('::ffff:192.0.2.50'), '192.0.2.50')
# a "last" ahead of this clock is no recent connection
infected({'192.0.2.67': entry(NOW + 3600, BAD2_MAC)})
iso.do_run(NOW + 40)
check('a "last" an hour ahead of the clock: not isolated', BAD2_MAC in state()['isolated'], False)
# a shorter duration set: an isolation held to it, from now
infected({'192.0.2.67': entry(NOW + 40, BAD2_MAC)})
iso.do_run(NOW + 50)
config(auto='1', hours='1')
iso.do_run(NOW + 60)
check('a shorter duration set: the isolation held to it, from now', state()['isolated'][BAD2_MAC]['until'],
      NOW + 60 + 3600)
# ifconfig that answers nothing: the firewall could take itself for a device - nothing new isolated, said
tool('nothing', 'true')
saved_ifconfig, iso.IFCONFIG = iso.IFCONFIG, os.path.join(BIN, 'nothing')
infected({'192.0.2.67': entry(NOW + 40, BAD2_MAC), '192.0.2.68': entry(NOW + 60, '02:00:00:00:66:03')})
try:
    answer = iso.do_run(NOW + 70)
finally:
    iso.IFCONFIG = saved_ifconfig
check("ifconfig that answers nothing: nothing new isolated, said; the isolated one stays",
      ('02:00:00:00:66:03' in state()['isolated'], BAD2_MAC in state()['isolated'], answer.get('message')),
      (False, True, "isolate: this firewall's own addresses could not be read; nothing new isolated"))
# the page: a list that could not be read is said so, not drawn as "off" and empty; names through plain()
with open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'PortGuard', 'index.volt'),
          encoding='utf-8') as fh:
    volt = fh.read()
check('the page: a list that could not be read is an error, not "off"',
      "data.status === 'failed' || typeof data.on !== 'boolean'" in volt, True)
check('the page: device names through plain()', volt.count("text(plain(d.name || ''))"), 2)
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- shared MACs, scopes, GUI and SSH, the HA peer

with open(os.path.join(FIX, 'arp'), encoding='utf-8') as fh:
    ARP_BEFORE = fh.read()
with open(os.path.join(FIX, 'ndp'), encoding='utf-8') as fh:
    NDP_BEFORE = fh.read()
SHARED_MAC, SPOOF_MAC, VIEWER_MAC = '02:00:00:00:77:01', '02:00:00:00:77:02', '02:00:00:00:77:03'
fixture('arp', ARP_BEFORE +
        '? (192.0.2.91) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.92) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.93) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (203.0.113.9) at %s on igb1 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.80) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.81) at 02:00:00:00:77:04 on igb0 expires in 900 seconds [ethernet]\n'
        % (SHARED_MAC, SHARED_MAC, SPOOF_MAC, SPOOF_MAC, VIEWER_MAC))
fixture('ndp', NDP_BEFORE + 'fe80::1%igb0                         02:00:00:00:00:fe  igb0 23h59m58s S R\n'
        'fe80::1%igb1                         02:00:00:00:10:01  igb1 23h59m58s S R\n')
check('NDP: a link-local address keeps its scope - two neighbours, two MAC addresses',
      sorted((k, v) for k, v in iso.neighbours().items() if k.startswith('fe80::1%')),
      [('fe80::1%igb0', GW_MAC), ('fe80::1%igb1', PC_MAC)])
# a login, not a connection: an SSH session from 192.0.2.80 (utmpx, as who prints it); pf's states - a half-open
# one from 192.0.2.81 to the firewall's SSH, the anti-lockout rule's - count for nothing
fixture('who', 'root             pts/0        Nov 17 10:00 (192.0.2.80)\n')
fixture('states-pf', 'all tcp 192.0.2.1:22 <- 192.0.2.81:40000       CLOSED:SYN_SENT\n'
        'all tcp 192.0.2.1:443 <- 192.0.2.81:40001       ESTABLISHED:ESTABLISHED\n')
config(auto='1', hours='2')
with open(CONFIG, encoding='utf-8') as fh:
    text = fh.read()
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(text.replace('<opnsense>', '<opnsense><hasync><pfsyncpeerip>192.0.2.95</pfsyncpeerip></hasync>', 1))
try:
    check('the HA peer, from config.xml', sorted(iso.ha_peers(iso.read_config())), ['192.0.2.95'])
    if os.path.exists(iso.STATE):
        os.remove(iso.STATE)
    infected({'192.0.2.91': entry(NOW + 100, SHARED_MAC), '192.0.2.93': entry(NOW + 100, SPOOF_MAC),
              '192.0.2.80': entry(NOW + 100, VIEWER_MAC), '192.0.2.95': entry(NOW + 100, '02:00:00:00:77:05'),
              '192.0.2.81': entry(NOW + 100, '02:00:00:00:77:04')})
    with open(CONFIG, encoding='utf-8') as fh:
        text = fh.read()
    with open(CONFIG, 'w', encoding='utf-8') as fh:
        fh.write(text.replace('<gateway>203.0.113.1</gateway>', '<gateway>203.0.113.9</gateway>'))
    iso.do_run(NOW + 110)
    skipped = state()['skipped']
    check('not isolated: one whose other address is the gateway; one logged in to SSH; the HA peer - each with why; '
          'one with only connections to the firewall\'s SSH and GUI is isolated, and so is a MAC address two IPv4 '
          'addresses share', ({a: skipped[a]['reason'] for a in skipped}, sorted(state()['isolated'])),
          ({'192.0.2.93': 'a gateway', '192.0.2.80': 'logged in to the web GUI or SSH of this firewall',
            '192.0.2.95': 'the HA peer'}, [SHARED_MAC, '02:00:00:00:77:04']))
    item = state()['isolated'].get(SHARED_MAC, {})
    check('... the shared one by the address that reached the list only, not its other client\'s',
          (item.get('shared'), item.get('held')), (True, ['192.0.2.91']))
finally:
    fixture('who', '')
    fixture('states-pf', '')
    fixture('arp', ARP_BEFORE)
    fixture('ndp', NDP_BEFORE)
with open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'PortGuard', 'index.volt'),
          encoding='utf-8') as fh:
    volt = fh.read()
check('the page words each new reason', all("'%s': \"{{ lang._(" % r in volt for r in (
    'the HA peer', 'logged in to the web GUI or SSH of this firewall')), True)
check('the page: a row shows what is held for it, says when no address of it is seen now and when it is shared',
      ["((d.holding || []).length ? d.holding : (d.addresses || [])).join(' ')" in volt,
       "if (!(d.addresses_now || []).length) {" in volt, 'if (d.shared) {' in volt], [True, True, True])
os.remove(iso.STATE)
infected({})
config(auto='1', hours='2')

# ---------------------------------------------------------------- once isolated: held whole, let go only at its end


def arp_line(ip, mac, extra='expires in 900 seconds'):
    return '? (%s) at %s on igb0 %s [ethernet]\n' % (ip, mac, extra)


def ndp_line(ip, mac):
    return '%-36s %s  igb0 23h59m58s S R\n' % (ip, mac)


ONE_MAC, TWO_MAC, NEW_HOLDER_MAC, VIP_MAC = ('02:00:00:00:88:01', '02:00:00:00:88:02', '02:00:00:00:88:03',
                                             '02:00:00:00:99:0a')
# a device with an IPv4 address and IPv6 ones is one device: every address held but its link-local one, here and
# on the page
fixture('arp', ARP_TEXT + arp_line('192.0.2.88', ONE_MAC))
fixture('ndp', NDP_BEFORE + ndp_line('2001:db8::88', ONE_MAC) + ndp_line('fe80::88%igb0', ONE_MAC))
infected({'192.0.2.88': entry(NOW + 100, ONE_MAC)})
iso.do_run(NOW + 110)
item = state()['isolated'].get(ONE_MAC, {})
check('an IPv4 address and an IPv6 one: one device, not shared - both held, not its link-local one',
      (item.get('shared'), item.get('held'), writes()[-1]), (False, ['192.0.2.88', '2001:db8::88'], ['192.0.2.88', '2001:db8::88']))
row = iso.do_list('', NOW + 115)['isolated'][0]
check('the page: what is held for it, and its addresses now - no link-local one', (row['holding'], row['addresses_now'],
      row['held'], row['shared']), (['192.0.2.88', '2001:db8::88'], ['192.0.2.88', '2001:db8::88'], True, False))
# quiet for 20 minutes, ARP and NDP forget it: what it had is held all the same, and the page says no address of it
# is seen now rather than that it is held at nothing
fixture('arp', ARP_TEXT)
fixture('ndp', NDP_BEFORE)
iso.do_run(NOW + 1400)
row = iso.do_list('', NOW + 1410)['isolated'][0]
check('ARP and NDP forget it: its addresses still held; the page says none is seen now',
      (iso.table_now(), row['addresses_now'], row['held']), (['192.0.2.88', '2001:db8::88'], [], True))
# it speaks again from a new IPv6 address: held from the next run, the others kept
fixture('arp', ARP_TEXT + arp_line('192.0.2.88', ONE_MAC))
fixture('ndp', NDP_BEFORE + ndp_line('2001:db8::8888', ONE_MAC))
iso.do_run(NOW + 1420)
check('a new address it takes: held from the next run, the old ones kept', iso.table_now(),
      ['192.0.2.88', '2001:db8::88', '2001:db8::8888'])
# it answers ARP for the address the page is opened from and for the gateway's: not let go, and neither address
# goes into the table
iso.do_list('192.0.2.50', NOW + 1430)
fixture('arp', ARP_TEXT.replace('(192.0.2.50) at %s' % ADMIN_MAC, '(192.0.2.50) at %s' % ONE_MAC)
        .replace('(203.0.113.1) at %s' % GW_MAC, '(203.0.113.1) at %s' % ONE_MAC) + arp_line('192.0.2.88', ONE_MAC))
answer = iso.do_run(NOW + 1440)
check('it answers ARP for the page client\'s and the gateway\'s addresses: not let go, neither address in the table, '
      'and not taken for a MAC address several devices share',
      (answer.get('let_go'), ONE_MAC in state()['isolated'], iso.table_now(), state()['isolated'].get(ONE_MAC, {}).get('shared')),
      ([], True, ['192.0.2.88', '2001:db8::88', '2001:db8::8888'], False))
st = state()
check('a link-local page client: not kept - it counts for nothing', (iso.remember_client(st, 'fe80::66', NOW + 1441),
      'fe80::66' in st.get('managers', {})), (False, False))
# it takes a second IPv4 address: not let go - shared from now on, what it had alone held, the new address not
fixture('arp', ARP_TEXT + arp_line('192.0.2.88', ONE_MAC) + arp_line('192.0.2.89', ONE_MAC))
n = len(logged)
answer = iso.do_run(NOW + 1450)
item = state()['isolated'].get(ONE_MAC, {})
check('a second IPv4 address it takes: not let go - shared from now, what it had alone held, the new one not',
      (answer.get('let_go'), item.get('shared'), iso.table_now()), ([], True, ['192.0.2.88', '2001:db8::88', '2001:db8::8888']))
check('... said in the system log', any('shows more than one IPv4 address' in line for line in logged[n:]), True)
# shared for the rest of its isolation: the second address gone again, a new one it shows is still not taken
fixture('arp', ARP_TEXT + arp_line('192.0.2.88', ONE_MAC))
fixture('ndp', NDP_BEFORE + ndp_line('2001:db8::8889', ONE_MAC))
iso.do_run(NOW + 1455)
check('shared for the rest of its isolation: a new address after the second one went is not taken either',
      (state()['isolated'].get(ONE_MAC, {}).get('shared'), iso.table_now()), (True, ['192.0.2.88', '2001:db8::88', '2001:db8::8888']))
# its MAC address turns out to be the firewall's own (ifconfig lists it): let go
with open(os.path.join(FIX, 'ifconfig'), encoding='utf-8') as fh:
    IFCONFIG_TEXT = fh.read()
fixture('ifconfig', IFCONFIG_TEXT + 'igb2: flags=8843<UP> mtu 1500\n\tether %s\n' % ONE_MAC)
answer = iso.do_run(NOW + 1460)
fixture('ifconfig', IFCONFIG_TEXT)
check('its MAC address the firewall\'s own: let go', (answer.get('let_go'), ONE_MAC in state()['isolated']), ([ONE_MAC], False))
# an address held for it that another device has now (ARP shows it there): no longer held
os.remove(iso.STATE)
fixture('arp', ARP_TEXT + arp_line('192.0.2.86', TWO_MAC))
fixture('ndp', NDP_BEFORE)
infected({'192.0.2.86': entry(NOW + 900, TWO_MAC)})
iso.do_run(NOW + 910)
before = iso.table_now()
fixture('arp', ARP_TEXT + arp_line('192.0.2.86', NEW_HOLDER_MAC))
iso.do_run(NOW + 1520)
row = iso.do_list('', NOW + 1525)['isolated'][0]
check('an address held for it that ARP shows under another MAC address now: let go of, said on the page',
      (before, iso.table_now(), row['holding'], row['held']), (['192.0.2.86'], [], [], False))
# the MAC address ARP shows at one of the firewall's own addresses (a CARP address's virtual one, which ifconfig
# does not list) is the firewall's: not isolated
os.remove(iso.STATE)
fixture('arp', ARP_TEXT + arp_line('192.0.2.1', VIP_MAC, 'permanent'))
infected({'192.0.2.60': entry(NOW + 1600, VIP_MAC)})
iso.do_run(NOW + 1610)
check('the MAC address at one of the firewall\'s own addresses: the firewall\'s, not isolated',
      (VIP_MAC in state()['isolated'], state()['skipped'].get('192.0.2.60', {}).get('reason')), (False, 'this firewall'))
# a link-local address names no MAC address without its scope: fe80::1 is a neighbour of every segment
check('a link-local exception: its MAC address only under its own scope',
      [iso.macs_for({'fe80::1%igb0': GW_MAC, 'fe80::1%igb1': PC_MAC}, k) for k in ('fe80::1%igb1', 'fe80::1', '2001:db8::5')],
      [[PC_MAC], [], []])
fixture('route-inet6', '   route to: default\n    gateway: fe80::1%igb1\n  interface: igb1\n')
with open(CONFIG, encoding='utf-8') as fh:
    whole = fh.read()
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(whole.replace('</Gateways>', '<gateway_item><name>LAN6_LL</name><interface>lan</interface><gateway>fe80::2'
                           '</gateway></gateway_item></Gateways>').replace('<opnsense>', '<opnsense><interfaces><lan>'
                           '<if>igb0</if></lan></interfaces>', 1))
check('gateways: a link-local one with its scope - from the default route, and from its interface in config.xml',
      sorted(k for k in iso.gateways(iso.read_config()) if k.startswith('fe80')), ['fe80::1%igb1', 'fe80::2%igb0'])
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(whole)
fixture('route-inet6', 'route: route has not been found\n')
fixture('arp', ARP_TEXT)
fixture('ndp', NDP_BEFORE)
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- the GUI's and SSH's exception: a login

fixture('who', 'root             pts/0        Nov 17 10:00 (192.0.2.80)\n'
        'admin            pts/1        Nov 17 10:05 (2001:db8::81)\n'
        'root             ttyu0        Nov 17 09:00\n'
        'root             pts/2        Nov 17 10:10 (fe80::66%igb0)\n'
        'root             pts/3        Nov 17 10:11 (admin-pc.example.net)\n')
check('SSH: the addresses utmpx shows logged in (who), a link-local one with its scope; not the console or a host '
      'name', sorted(iso.ssh_logins()), ['192.0.2.80', '2001:db8::81', 'fe80::66%igb0'])
fixture('who', '')


def audit(when, program, message):
    """A line of OPNsense's audit log, RFC 5424, into the file of its day."""
    path = iso.AUDIT_LOG.format(day=time.strftime('%Y%m%d', time.gmtime(when)))
    with open(path, 'a', encoding='utf-8') as fh:
        fh.write('<38>1 %s fw.example.net %s 4242 - [meta sequenceId="1"] %s\n' % (
            time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(when)), program, message))


LOGIN = "/index.php: Successful login for user 'root' from: %s"
audit(NOW - 600, 'audit', LOGIN % '192.0.2.82')                 # ten minutes ago: the day before's file
audit(NOW - 5 * 3600, 'audit', LOGIN % '192.0.2.83')            # five hours ago: past the session timeout
audit(NOW - 300, 'audit', "/index.php: Web GUI authentication error for 'root' from 192.0.2.84")
audit(NOW - 300, 'audit', 'user root could not authenticate for WebGui. [using x + y]')
audit(NOW - 300, 'lighttpd', LOGIN % '192.0.2.85')              # another program's line
audit(NOW - 300, 'audit', LOGIN % 'fe80::86')                   # a link-local address
audit(NOW - 300, 'audit', LOGIN % "192.0.2.99' from: 192.0.2.87")   # a user name made to look like an address
audit(NOW + 60, 'audit', "/index.php: Successful login for user 'root' from: 192.0.2.89 extra")
with open(iso.AUDIT_LOG.format(day=time.strftime('%Y%m%d', time.gmtime(NOW))), 'a', encoding='utf-8') as fh:
    fh.write("<38>1 not-a-time fw.example.net audit 4242 - - %s\n" % (LOGIN % '192.0.2.88'))
check('GUI: the logins of the audit log within the session timeout (240 minutes); not an older one, a failed one, '
      'another program\'s; the address taken from the end', sorted(iso.gui_logins(iso.read_config(), NOW)),
      ['192.0.2.82', '192.0.2.87', 'fe80::86'])
with open(CONFIG, encoding='utf-8') as fh:
    whole = fh.read()
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(whole.replace('<opnsense>', '<opnsense><system><webgui><session_timeout>600</session_timeout></webgui>'
                                         '</system>', 1))
check('GUI: a session timeout of 600 minutes set - the login five hours ago counts too',
      sorted(iso.gui_logins(iso.read_config(), NOW)), ['192.0.2.82', '192.0.2.83', '192.0.2.87', 'fe80::86'])
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(whole)
check('an RFC 5424 time as Unix seconds, its offset taken off', [iso.stamp(t) for t in (
    '2025-11-17T04:00:00+04:00', '2025-11-17T00:00:00.123456Z', '2025-11-16T19:00:00-0500', '2025-13-01T00:00:00Z', 'x')],
      [NOW, NOW, NOW, None, None])
# a device logged in to the GUI is not isolated, nor one logged in to SSH; an isolated device's link-local SSH login
# lets it go no more than anything else it does
fixture('arp', ARP_TEXT + arp_line('192.0.2.82', TWO_MAC) + arp_line('192.0.2.88', ONE_MAC))
fixture('ndp', NDP_BEFORE + ndp_line('fe80::88%igb0', ONE_MAC))
fixture('who', 'root             pts/0        Nov 17 10:00 (fe80::88%igb0)\n')
infected({'192.0.2.82': entry(NOW - 30, TWO_MAC), '192.0.2.88': entry(NOW - 30, ONE_MAC)})
iso.do_run(NOW)
check('logged in to the GUI: not isolated, with why; one logged in to SSH from its link-local address only is',
      (state()['skipped'].get('192.0.2.82', {}).get('reason'), sorted(state()['isolated'])),
      ('logged in to the web GUI or SSH of this firewall', [ONE_MAC]))
answer = iso.do_run(NOW + 60)
check('an isolated device logged in to SSH from its link-local address: not let go', (answer.get('let_go'),
      ONE_MAC in state()['isolated']), ([], True))
fixture('who', '')
fixture('arp', ARP_TEXT)
fixture('ndp', NDP_BEFORE)
for name in os.listdir(AUDIT):
    os.remove(os.path.join(AUDIT, name))
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- which device: the one ARP shows at the address

# os-netreport names the address's previous holder (its scan had not seen the new one, and it never clears a
# MAC address it once wrote): the device ARP shows there now is isolated, and the address that reached the list
# is blocked
PREV_MAC, NEXT_MAC = '02:00:00:00:30:01', '02:00:00:00:30:02'
fixture('arp', ARP_TEXT + arp_line('192.0.2.66', OTHER_MAC) + arp_line('192.0.2.30', PREV_MAC))
infected({'192.0.2.66': entry(NOW - 30, PREV_MAC, name='printer')})
n = len(logged)
iso.do_run(NOW)
check('os-netreport names the previous holder, ARP shows another now: the one ARP shows isolated, the address that '
      'reached the list blocked', (sorted(state()['isolated']), iso.table_now()), ([OTHER_MAC], ['192.0.2.66']))
check('... said in the system log', any(('os-netreport names %s' % PREV_MAC) in line for line in logged[n:]), True)
check('... and the name os-netreport gives the device it names is not given to the one isolated',
      state()['isolated'][OTHER_MAC]['name'], '')
fixture('arp', ARP_TEXT + arp_line('192.0.2.66', PREV_MAC))
iso.do_run(NOW + 60)
check('... kept for that "last": ARP showing the first holder there again does not hand it back',
      (sorted(state()['isolated']), state()['macs'].get('192.0.2.66', {}).get('mac')), ([OTHER_MAC], OTHER_MAC))
infected({'192.0.2.66': entry(NOW + 100, PREV_MAC, name='printer')})
iso.do_run(NOW + 110)
check('... a newer "last", ARP and os-netreport agreeing: that one isolated, with its name, and kept for that "last"',
      (sorted(state()['isolated']), state()['isolated'][PREV_MAC]['name'], state()['macs'].get('192.0.2.66', {}).get('mac')),
      ([OTHER_MAC, PREV_MAC], 'printer', PREV_MAC))
# found by agreeing, the device is kept as well: one that takes the address afterwards is not taken for that "last"
fixture('arp', ARP_TEXT + arp_line('192.0.2.66', NEXT_MAC))
iso.do_run(NOW + 170)
check('... ARP showing a third device there afterwards, the same "last": not taken for it',
      sorted(state()['isolated']), [OTHER_MAC, PREV_MAC])
# ARP showing nothing at the first reading: the device os-netreport names, kept for that "last" all the same
os.remove(iso.STATE)
fixture('arp', ARP_TEXT)
infected({'192.0.2.66': entry(NOW + 200, PREV_MAC)})
iso.do_run(NOW + 210)
fixture('arp', ARP_TEXT + arp_line('192.0.2.66', NEXT_MAC))
iso.do_run(NOW + 270)
check('ARP showing nothing at first: the device os-netreport names, kept - one ARP shows there afterwards is not taken',
      (sorted(state()['isolated']), state()['macs'].get('192.0.2.66', {}).get('mac')), ([PREV_MAC], PREV_MAC))
fixture('arp', ARP_TEXT)
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- many addresses: on pfctl's stdin, 64 a device


def calls():
    try:
        with open(CALLS, encoding='utf-8') as fh:
            return [json.loads(line) for line in fh]
    except OSError:
        return []


def said_too_many(since):
    return len([line for line in logged[since:] if 'has more than 64 addresses' in line])


# a device NDP shows with a hundred IPv6 addresses (one making them up): the table takes 64 of them, the address that
# reached the list among them; pfctl's command line carries none; the system log says so, once an hour at most
SPRAY_MAC, SPRAY2_MAC = '02:00:00:00:55:01', '02:00:00:00:55:02'
fixture('arp', ARP_TEXT + arp_line('192.0.2.55', SPRAY_MAC))
fixture('ndp', NDP_BEFORE + ''.join(ndp_line('2001:db8:55::%x' % i, SPRAY_MAC) for i in range(1, 101)))
infected({'192.0.2.55': entry(NOW - 30, SPRAY_MAC)})
n = len(logged)
iso.do_run(NOW)
item = state()['isolated'].get(SPRAY_MAC, {})
check('a device NDP shows with 100 addresses: 64 held, the one that reached the list among them, and 64 kept',
      (len(iso.table_now()), '192.0.2.55' in iso.table_now(), len(item.get('held', [])), len(item.get('seen', {}))),
      (64, True, 64, 64))
check('... pfctl given them on its stdin, none on its command line',
      [c for c in calls() if 'replace' in c][-1], ['-t', 'portguard_isolated', '-T', 'replace', '-f', '-'])
check('... said in the system log', said_too_many(n), 1)
iso.do_run(NOW + 60)
check('... not again every minute', said_too_many(n), 1)
iso.do_run(NOW + 3700)
check('... but again an hour later', said_too_many(n), 2)
# a device that reached the list from 70 addresses: 64 of them kept as the ones that reached it, and held
infected(dict(('2001:db8:56::%x' % i, entry(NOW + 3700, SPRAY2_MAC)) for i in range(1, 71)))
iso.do_run(NOW + 3710)
item = state()['isolated'].get(SPRAY2_MAC, {})
check('a device that reached the list from 70 addresses: 64 of them kept, and held',
      (len(item.get('addresses', [])), len(item.get('held', []))), (64, 64))
fixture('arp', ARP_TEXT)
fixture('ndp', NDP_BEFORE)
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- config.xml read once, under OPNsense's lock

# OPNsense's Config::save() rewrites config.xml in place under an exclusive lock: a run waits for it, and
# one that cannot have it in time changes nothing - nor does Undo; the list says it failed
infected({'192.0.2.66': entry(NOW + 100, BAD_MAC)})
holder = open(CONFIG, 'rb')
fcntl.flock(holder, fcntl.LOCK_EX)
saved_wait, iso.WAIT = iso.WAIT, 1
try:
    answer = iso.do_run(NOW + 110)
    listing = iso.do_list('', NOW + 110)
finally:
    fcntl.flock(holder, fcntl.LOCK_UN)
    iso.WAIT = saved_wait
check('config.xml held by its writer: the run changes nothing and says so, the list is a failure',
      (answer.get('message'), os.path.exists(iso.STATE), listing.get('status')),
      ('isolate: config.xml could not be read; nothing changed', False, 'failed'))
check('... and the next run reads it', BAD_MAC in (iso.do_run(NOW + 120).get('isolated') or []), True)
fcntl.flock(holder, fcntl.LOCK_EX)
iso.WAIT = 1
try:
    answer = iso.do_undo(BAD_MAC, '', NOW + 125)
finally:
    fcntl.flock(holder, fcntl.LOCK_UN)
    holder.close()
    iso.WAIT = saved_wait
check('... Undo while it is held: failed, the device still isolated', (answer.get('status'), BAD_MAC in state()['isolated']),
      ('failed', True))
iso.do_undo(BAD_MAC, '', NOW + 126)
# config.xml emptied by a rewrite after the run read it: every part of the run goes on that one reading - the
# router of a static gateway, which only config.xml names, stays an exception
os.remove(iso.STATE)
ROUTER_MAC = '02:00:00:00:99:01'
with open(CONFIG, encoding='utf-8') as fh:
    whole = fh.read()
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(whole.replace('</Gateways>', '<gateway_item><name>LAN_RTR</name><gateway>192.0.2.254</gateway>'
                                          '</gateway_item></Gateways>'))
fixture('arp', ARP_TEXT + '? (192.0.2.254) at %s on igb0 expires in 900 seconds [ethernet]\n' % ROUTER_MAC)
infected({'192.0.2.254': entry(NOW + 130, ROUTER_MAC)})
real_neighbours = iso.neighbours


def neighbours_after_a_rewrite():
    open(CONFIG, 'w').close()
    return real_neighbours()


iso.neighbours = neighbours_after_a_rewrite
try:
    iso.do_run(NOW + 140)
finally:
    iso.neighbours = real_neighbours
    with open(CONFIG, 'w', encoding='utf-8') as fh:
        fh.write(whole)
    fixture('arp', ARP_TEXT)
check('config.xml emptied by a rewrite after the run read it: the router of a static gateway still an exception',
      (ROUTER_MAC in state()['isolated'], state()['skipped'].get('192.0.2.254', {}).get('reason')), (False, 'a gateway'))
# Undo writes the table as a run does: another isolated device answering ARP for the gateway's address by
# then does not put that address into the table
os.remove(iso.STATE)
fixture('arp', ARP_TEXT + '? (192.0.2.66) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.67) at %s on igb0 expires in 900 seconds [ethernet]\n' % (BAD_MAC, BAD2_MAC))
infected({'192.0.2.66': entry(NOW + 150, BAD_MAC), '192.0.2.67': entry(NOW + 150, BAD2_MAC)})
iso.do_run(NOW + 160)
fixture('arp', ARP_TEXT.replace('(203.0.113.1) at %s' % GW_MAC, '(203.0.113.1) at %s' % BAD2_MAC) +
        '? (192.0.2.66) at %s on igb0 expires in 900 seconds [ethernet]\n'
        '? (192.0.2.67) at %s on igb0 expires in 900 seconds [ethernet]\n' % (BAD_MAC, BAD2_MAC))
iso.do_undo(BAD_MAC, '', NOW + 170)
check('Undo writes the table with the exceptions: a gateway\'s address never in it', '203.0.113.1' in writes()[-1], False)
fixture('arp', ARP_TEXT)
os.remove(iso.STATE)
infected({})
# the alias there but its table not (a filter reload that failed) and nothing isolated: nothing to do, and no
# failure written into the system log every minute
os.remove(TABLE)
n = len(logged)
answer = iso.do_run(NOW + 180)
open(TABLE, 'w').close()
check('no table, nothing isolated: no failure, nothing logged', (answer['firewall']['status'], logged[n:]), ('ok', []))
# a MAC alias of that name, an earlier build's, is OPNsense's to fill: not written, said until Apply
config(auto='1', hours='2', aliases='<alias><name>portguard_isolated</name><enabled>1</enabled><type>mac</type>'
                                     '<content>%s</content></alias>' % BAD_MAC)
os.remove(iso.STATE)
infected({'192.0.2.66': entry(NOW + 190, BAD_MAC)})
n = len(writes())
answer = iso.do_run(NOW + 200)
check('a MAC alias by that name: its table not written, the run says why', (len(writes()) - n, answer['firewall'].get('errors')),
      (0, ['the alias portguard_isolated is not an external alias: Apply on the Settings tab makes it one']))
check('the alias\'s state: missing, switched off, ready', [iso.alias_state(iso.ET.fromstring(
    '<opnsense><OPNsense><Firewall><Alias><aliases>%s</aliases></Alias></Firewall></OPNsense></opnsense>' % a))
    for a in ('', ISOLATED_ALIAS.replace('<enabled>1', '<enabled>0'), ISOLATED_ALIAS)], ['missing', 'off', 'ready'])
config(auto='1', hours='2')
os.remove(iso.STATE)
infected({})

# ---------------------------------------------------------------- cut.py, the isolated table

KILLS = os.path.join(TOP, 'kills')
fixture('pf-portguard_blocked', '   192.0.2.10\n')
fixture('pf-portguard_isolated', '   192.0.2.66\n   2001:db8::66\n')
fixture('states', 'all tcp 192.0.2.66:51000 -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED\n'
        '   [1 + 2]  [3 + 4]\n   age 00:01:00, expires in 23:59:00, 10:10 pkts, 1000:1000 bytes, rule 5\n'
        '   id: 00000000000000aa creatorid: 00000001\n'
        'all udp 2001:db8::66[5353] -> 2001:db8::1[53]       MULTIPLE:SINGLE\n'
        '   id: 00000000000000bb creatorid: 00000001\n'
        'all tcp 192.0.2.10:52000 -> 198.51.100.8:443       ESTABLISHED:ESTABLISHED\n'
        '   id: 00000000000000cc creatorid: 00000001\n'
        'all tcp 192.0.2.99:53000 -> 198.51.100.9:443       ESTABLISHED:ESTABLISHED\n'
        '   id: 00000000000000dd creatorid: 00000001\n')
tool('pfctl', '''case "$1 $2 $3 $4" in
"-t "*" -T show") f="%s/pf-$2"; [ -f "$f" ] && cat "$f" || exit 1 ;;
"-ss -vv"*) cat "%s/states" ;;
"-k id -k "*) echo "$4" >> "%s" ;;
esac''' % (FIX, FIX, KILLS))

cut = load('cut')
cut.CONFIG = CONFIG
cut.STATE_DIR = os.path.join(TOP, 'cut')
cut.STATUS = os.path.join(cut.STATE_DIR, 'status.json')
cut.SNAPSHOT = os.path.join(cut.STATE_DIR, 'portguard_blocked.json')
cut.ISOLATED_SNAPSHOT = os.path.join(cut.STATE_DIR, 'portguard_isolated.json')
cut.PFCTL = os.path.join(BIN, 'pfctl')
cut.log = logged.append
os.makedirs(cut.STATE_DIR)


def kills():
    try:
        with open(KILLS, encoding='utf-8') as fh:
            return sorted(line.strip() for line in fh)
    except OSError:
        return []


ALIASES = ('<alias><name>portguard_blocked</name><enabled>1</enabled><type>mac</type><content>%s</content></alias>'
           '<alias><name>portguard_isolated</name><enabled>1</enabled><type>mac</type><content>%s</content></alias>'
           % (PC_MAC, BAD_MAC))
config(auto='0', aliases=ALIASES)
check('cut: the isolated table not watched with automatic isolation off', cut.watched(table=cut.ISOLATED), False)
config(auto='1', aliases=ALIASES)
check('cut: the isolated table watched with it on and its alias there', cut.watched(table=cut.ISOLATED), True)
config(auto='1', enabled='0', aliases=ALIASES)
summary = cut.run()
check('cut: blocked devices off, isolation on - only the isolated devices\' states killed', kills(),
      ['00000000000000aa', '00000000000000bb'])
check('cut: the summary keeps the blocked table at the top and the isolated under "isolated"',
      (summary['watched'], summary['isolated']['watched'], summary['isolated']['cut']), (False, True, 2))
check('cut: the isolated table\'s own snapshot', cut.load(cut.ISOLATED_SNAPSHOT, None), ['192.0.2.66/32', '2001:db8::66/128'])
os.remove(KILLS)
cut.run()
check('cut: a second run, nothing new in the table: nothing killed', kills(), [])
config(auto='1', aliases=ALIASES)
cut.run()
check('cut: blocked devices on again - their table cut as before', kills(), ['00000000000000cc'])
config(auto='0', aliases=ALIASES)
cut.run()
check('cut: isolation off - the isolated snapshot forgotten, the blocked one kept',
      (os.path.exists(cut.ISOLATED_SNAPSHOT), os.path.exists(cut.SNAPSHOT)), (False, True))

# ---------------------------------------------------------------- the rules hook (php)

PHP = shutil.which('php')
if PHP:
    harness = os.path.join(TOP, 'rules.php')
    with open(harness, 'w', encoding='utf-8') as fh:
        fh.write('''<?php
namespace OPNsense\\Firewall { class Plugin { public $rules = [];
    public function registerFilterRule($prio, $conf) { $this->rules[] = $conf['descr'] . ' ' . $conf['ipprotocol']; } } }
namespace {
require $argv[1];
$alias = function ($name, $on) { return ['name' => $name, 'enabled' => $on, 'type' => 'mac', 'content' => '02:00:00:00:66:01']; };
$config = ['OPNsense' => ['PortGuard' => ['general' => json_decode($argv[2], true)],
    'Firewall' => ['Alias' => ['aliases' => ['alias' => array_map(function ($a) use ($alias) { return $alias($a[0], $a[1]); },
    json_decode($argv[3], true))]]]]];
$fw = new OPNsense\\Firewall\\Plugin();
portguard_firewall($fw);
echo json_encode($fw->rules);
}
''')
    INC = os.path.join(ROOT, 'src', 'etc', 'inc', 'plugins.inc.d', 'portguard.inc')

    def rules(general, aliases):
        out = subprocess.run([PHP, harness, INC, json.dumps(general), json.dumps(aliases)], capture_output=True,
                             text=True, timeout=30)
        try:
            return sorted(json.loads(out.stdout))
        except ValueError:
            return out.stdout + out.stderr

    both = [['portguard_blocked', '1'], ['portguard_isolated', '1']]
    iso_rules = ['Port Guard: isolated devices in inet', 'Port Guard: isolated devices in inet6',
                 'Port Guard: isolated devices out inet', 'Port Guard: isolated devices out inet6']
    blk_rules = [r.replace('isolated', 'blocked') for r in iso_rules]
    check('rules: blocked devices on, isolation off by default: the four blocked rules only',
          rules({'enabled': '1'}, both), blk_rules)
    check('rules: both on: eight rules', rules({'enabled': '1', 'auto_isolate': '1'}, both), sorted(blk_rules + iso_rules))
    check('rules: blocked devices off, isolation on: the four isolated rules only',
          rules({'enabled': '0', 'auto_isolate': '1'}, both), iso_rules)
    check('rules: isolation on, its alias missing: none of its rules',
          rules({'enabled': '0', 'auto_isolate': '1'}, [['portguard_blocked', '1']]), [])
    check('rules: isolation on, its alias off: none of its rules',
          rules({'enabled': '0', 'auto_isolate': '1'}, [['portguard_isolated', '0']]), [])
else:
    print('skip the rules hook: no php here')

shutil.rmtree(TOP, ignore_errors=True)
print('%d failure(s)' % failures)
sys.exit(1 if failures else 0)
