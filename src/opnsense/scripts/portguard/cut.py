#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""Cut the connections a listed device already has open.

The rules plugins.inc.d/portguard.inc registers stop what is new: pf matches a packet against the
states it holds before it looks at a rule, so a connection a device opened before it was listed keeps
its state and goes on - and on an XGS with offloading on, in the coprocessor too, for as long as it
carries traffic. Nothing in Port Guard cut one until 2026-10-29, though its page and README said that
nothing a listed device sends passes the firewall. This compares pf's table of the blocked devices,
portguard_blocked, with what it held at the last run, and kills, by id, every pf state with either end
in what was added: when Apply puts the list into the firewall (apply.php runs it after the aliases are
refreshed), and every minute (cron.d/portguard) for an address the alias gains later - a new lease, a
new IPv6 address of a device listed. A coprocessor's flow goes with its state: os-xgs-npu's drivers
take a connection out of hardware once pf no longer holds it.

    cut.py            run once, print a JSON summary (apply.php; cron, every minute)
    cut.py --status   print the last run's record

Always on: listing a device means its open connections too, and the page has no switch for it. Built
on 2026-10-29 from os-blocklists' cut.py, with that one's lessons of the same day: the first run takes
everything in the table as new, and what the table held is forgotten when the alias goes or Port Guard
is turned off, so blocking again starts from nothing and cuts what is listed; it is written only when
the table changed, and by one run at a time. A state is killed by its id, as os-blocklists' are - one
by its hosts (`pfctl -k <host> -k <host>`) killed nothing there. Never fails its caller; what it could
not do is in the summary and in the system log, under portguard.
"""
import bisect
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
STATE_DIR = '/var/db/os-portguard/cut'
STATUS = os.path.join(STATE_DIR, 'status.json')
SNAPSHOT = os.path.join(STATE_DIR, 'portguard_blocked.json')
LOCK = os.path.join(STATE_DIR, 'lock')
PFCTL = '/sbin/pfctl'
TABLE = 'portguard_blocked'
TAG = 'portguard'
WAIT = 10           # seconds a run waits for another to end, then leaves the cutting to the next minute


def log(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def watched(path=CONFIG):
    """True when the blocked devices' table is to be watched - Port Guard on, its alias there and on;
    False when it is not; None when config.xml cannot be read - nothing is cut then, and nothing
    forgotten."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    if (root.findtext('OPNsense/PortGuard/general/enabled') or '1') != '1':
        return False
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        if alias.findtext('name') == TABLE:
            return (alias.findtext('enabled') or '1') == '1'
    return False


def table_entries(name):
    """What pf's table holds now, as networks; None when there is no such table."""
    try:
        r = subprocess.run([PFCTL, '-t', name, '-T', 'show'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    out = set()
    for line in r.stdout.splitlines():
        item = line.strip()
        if not item or item.startswith('!'):     # a negated entry excludes, it does not list
            continue
        try:
            out.add(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return out


class Matcher:
    """Is an address inside any of a set of networks: each family's networks as sorted, merged
    integer ranges, so a state's addresses are looked up by bisection however long the list."""

    def __init__(self, networks):
        self.ranges = {4: [], 6: []}
        for n in networks:
            net = ipaddress.ip_network(n, strict=False)
            self.ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.starts = {}
        for v, rs in self.ranges.items():
            rs.sort()
            merged = []
            for a, b in rs:
                if merged and a <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], b))
                else:
                    merged.append((a, b))
            self.ranges[v] = merged
            self.starts[v] = [a for a, _ in merged]

    def __contains__(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        rs = self.ranges[ip.version]
        i = bisect.bisect_right(self.starts[ip.version], int(ip)) - 1
        return i >= 0 and rs[i][0] <= int(ip) <= rs[i][1]


ADDR_V6 = re.compile(r'^([0-9A-Fa-f:.]+)\[\d+\]$')


def state_addresses(line):
    """Every address on the first line of a state in `pfctl -ss -vv`: both ends, and the translated
    one in parentheses. IPv4 is written address:port, IPv6 address[port]."""
    out = []
    for tok in line.split()[2:]:
        tok = tok.strip('()')
        m = ADDR_V6.match(tok)
        if m:
            cand = m.group(1)
        elif tok.count(':') == 1 and '.' in tok:
            cand = tok.split(':', 1)[0]
        else:
            cand = tok
        try:
            out.append(str(ipaddress.ip_address(cand)))
        except ValueError:
            continue
    return out


def states(text):
    """[(id, [addresses])] from `pfctl -ss -vv`."""
    out, addrs = [], None
    for line in text.splitlines():
        if line and not line[0].isspace():
            addrs = state_addresses(line)
            continue
        m = re.match(r'\s+id: ([0-9a-f]+)', line)
        if m and addrs is not None:
            out.append((m.group(1), addrs))
            addrs = None
    return out


def load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save(path, data):
    """Through a temporary file of this run's own beside it, renamed over it: a reader never meets half
    a file, and two runs never write into the same temporary one."""
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


def forget():
    """What the table held, deleted, so blocking again starts from nothing (see the top); and a
    temporary file a stopped run left behind - only the run holding the lock writes here."""
    for entry in os.listdir(STATE_DIR):
        if entry.startswith('.') or os.path.join(STATE_DIR, entry) == SNAPSHOT:
            try:
                os.unlink(os.path.join(STATE_DIR, entry))
            except OSError:
                pass


def plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def run():
    status = load(STATUS, {})
    on = watched()
    summary = {'run': int(time.time()), 'watched': bool(on), 'cut': 0, 'total': status.get('total', 0)}
    if not on:
        if on is False:
            forget()
            summary['message'] = 'cut: no device listed, or Port Guard off'
        else:
            summary['message'] = 'cut: config.xml could not be read'
        # once a minute with nothing to watch: written only when it says something new
        if status.get('message') != summary['message']:
            save(STATUS, summary)
        return summary

    now = table_entries(TABLE)
    if now is None:
        summary['error'] = 'no pf table by this name - is the alias loaded?'
        summary['message'] = 'cut: ' + summary['error']
        save(STATUS, summary)
        return summary
    before = load(SNAPSHOT, None)
    kept = None if before is None else set(before)
    new = now if kept is None else now - kept
    summary.update({'entries': len(now), 'added': len(new)})

    if new:
        try:
            text = subprocess.run([PFCTL, '-ss', '-vv'], capture_output=True, text=True, timeout=120).stdout
        except (OSError, subprocess.SubprocessError):
            text = ''
        match = Matcher(new)
        for sid, addrs in states(text):
            if not any(a in match for a in addrs):
                continue
            r = subprocess.run([PFCTL, '-k', 'id', '-k', sid], capture_output=True, timeout=30)
            if r.returncode == 0:
                summary['cut'] += 1

    # what was compared, not a second reading: an address added since is new at the next run; and
    # written only when it is not what was kept already
    if now != kept:
        save(SNAPSHOT, sorted(now))
    if new or summary['cut']:
        log(f"{TABLE}: {plural(len(new), 'new address', 'new addresses')} of {len(now)}, "
            f"{plural(summary['cut'], 'open connection')} cut")
    summary['total'] += summary['cut']
    summary['message'] = (f"cut: {plural(len(now), 'address', 'addresses')} blocked, "
                          f"{summary['cut']} cut now, {summary['total']} in all")
    save(STATUS, summary)
    return summary


def take(lock, wait=WAIT):
    """The lock, or False after `wait` seconds: one run at a time - Apply's and the minute's. The
    minute's run lasts a second or two, and one begun before an Apply has not seen the device just
    listed, so a run that meets another waits for it rather than giving up at once - then leaves the
    cutting to the next minute."""
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
    if '--status' in argv:
        print(json.dumps(load(STATUS, {}), sort_keys=True))
        return 0
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOCK, 'w') as lock:
            if not take(lock):
                last = load(STATUS, {})
                print(json.dumps({'message': last.get('message', 'cut: another run is cutting'), 'cut': 0},
                                 sort_keys=True))
                return 0
            print(json.dumps(run(), sort_keys=True))
    except Exception as e:      # never fail the caller: cron or apply.php
        log(f'stopped: {e}')
        print(json.dumps({'message': f'cut: stopped - {e}', 'cut': 0}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
