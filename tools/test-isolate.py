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
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

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
with open(os.path.join(ROUTERS, 'igb2_routerv6'), 'w', encoding='utf-8') as fh:
    fh.write('2001:db8:ffff::1\n')
with open(os.path.join(ROUTERS, 'igb0_nameserver'), 'w', encoding='utf-8') as fh:
    fh.write('198.51.100.200\n')

# pfctl stands in for the isolated devices' table: a file holds what it holds, every replace or flush is recorded
# (WRITES, the addresses as a JSON list a line), and it lists no state; cut.py stands in, counting its runs
TABLE = os.path.join(TOP, 'table-portguard_isolated')
WRITES = os.path.join(TOP, 'writes.jsonl')
CUTS = os.path.join(TOP, 'cuts')
pf = os.path.join(TOP, 'pfctl-table.py')
with open(pf, 'w', encoding='utf-8') as fh:
    fh.write('''import json, os, sys
table, writes, args = sys.argv[1], sys.argv[2], sys.argv[3:]
if args[:1] == ['-ss']:
    sys.exit(0)
if args[:2] != ['-t', 'portguard_isolated'] or not os.path.exists(table):
    sys.stderr.write('pfctl: Table does not exist.\\n')
    sys.exit(1)
op = args[3] if len(args) > 3 else ''
if op == 'show':
    sys.stdout.write(open(table).read())
elif op in ('replace', 'flush'):
    addrs = sorted(args[4:]) if op == 'replace' else []
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
check('gateways: config.xml, /tmp router files, the default route', sorted(iso.gateways()),
      ['2001:db8:ffff::1', '203.0.113.1'])
check('neighbours from ARP and NDP, incomplete ones left out', iso.neighbours(),
      {'203.0.113.1': GW_MAC, '192.0.2.10': PC_MAC, '192.0.2.50': ADMIN_MAC, '2001:db8::66': BAD_MAC})

# ---------------------------------------------------------------- off by default

infected({'192.0.2.66': entry(NOW - 60, BAD_MAC)})
config()
check('settings: off by default, 24 hours', iso.settings(), (False, 24))
check('off by default: nothing isolated', iso.do_run(NOW).get('message'), 'isolate: off')
check('off by default: no state written, no alias', (os.path.exists(iso.STATE), writes()), (False, []))
config(auto='0')
check('off: nothing isolated', iso.do_run(NOW).get('message'), 'isolate: off')

# ---------------------------------------------------------------- isolating

config(auto='1', hours='2')
check('settings: on, 2 hours', iso.settings(), (True, 2))
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
check('the table made to hold the address the isolated MAC address has now (NDP), not the others\'',
      writes(), [['2001:db8::66']])
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
check('a duration out of range is held to 720 hours', iso.settings(), (True, 720))
config(auto='1', hours='x')
check('a duration that is not a number: 24 hours', iso.settings(), (True, 24))
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
# pf's states: one to the GUI's port, one to SSH's, one to another port of the firewall, and one through it
tool('pfctl-states', 'cat <<EOF\n'
     'all tcp 192.0.2.1:443 <- 192.0.2.80:51515       ESTABLISHED:ESTABLISHED\n'
     'all tcp 2001:db8::1[22] <- 2001:db8::81[52525]       ESTABLISHED:ESTABLISHED\n'
     'all udp 192.0.2.1:53 <- 192.0.2.81:53535       SINGLE:MULTIPLE\n'
     'all tcp 198.51.100.7:443 <- 192.0.2.81:54545       ESTABLISHED:ESTABLISHED\n'
     'EOF')
saved_pfctl, iso.PFCTL = iso.PFCTL, os.path.join(BIN, 'pfctl-states')
config(auto='1', hours='2')
with open(CONFIG, encoding='utf-8') as fh:
    text = fh.read()
with open(CONFIG, 'w', encoding='utf-8') as fh:
    fh.write(text.replace('<opnsense>', '<opnsense><hasync><pfsyncpeerip>192.0.2.95</pfsyncpeerip></hasync>', 1))
try:
    check('the addresses with a connection open to the GUI or SSH port, IPv4 and IPv6; not another port, not '
          'through the firewall', sorted(iso.managing(iso.own()[0])), ['192.0.2.80', '2001:db8::81'])
    check('the HA peer, from config.xml', sorted(iso.ha_peers()), ['192.0.2.95'])
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
    check('not isolated: a MAC address two IPv4 addresses share; one whose other address is the gateway; a connection '
          'to the GUI; the HA peer - each with why; a connection to another port is isolated',
          ({a: skipped[a]['reason'] for a in skipped}, sorted(state()['isolated'])),
          ({'192.0.2.91': 'a MAC address several devices share', '192.0.2.93': 'a gateway',
            '192.0.2.80': 'a connection to the web GUI or SSH of this firewall', '192.0.2.95': 'the HA peer'},
           ['02:00:00:00:77:04']))
finally:
    iso.PFCTL = saved_pfctl
    fixture('arp', ARP_BEFORE)
    fixture('ndp', NDP_BEFORE)
with open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'PortGuard', 'index.volt'),
          encoding='utf-8') as fh:
    volt = fh.read()
check('the page words each new reason', all("'%s': \"{{ lang._(" % r in volt for r in (
    'the HA peer', 'a connection to the web GUI or SSH of this firewall', 'a MAC address several devices share')), True)
os.remove(iso.STATE)
infected({})
config(auto='1', hours='2')

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
