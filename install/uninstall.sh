#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Port Guard plugin files. The rules go with the filter reload run here, because they are
# registered by the hook removed below. Kept: the settings, and the portguard_blocked alias in
# Firewall: Aliases, which blocks nothing without the rules - remove it there when no longer wanted,
# or turn Port Guard off and Apply before removing it, which removes it and empties its table.

# the cron entry first, and the rules hook, which would stop a filter reload if it outlived its model
rm -f /usr/local/etc/cron.d/portguard
# A cut already running stops now, rather than after its files went (2026-10-29). The bracket keeps
# the pattern from matching a shell that carries this text.
/bin/pkill -f '/usr/local/opnsense/scripts/[p]ortguard/' 2> /dev/null || true
rm -f /usr/local/etc/inc/plugins.inc.d/portguard.inc
rm -rf /usr/local/share/os-portguard
rm -f /usr/local/opnsense/service/conf/actions.d/actions_portguard.conf
rm -rf /usr/local/opnsense/scripts/portguard
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/PortGuard
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/PortGuard
# what cut.py kept - the table's last reading - which is no file of src/'s: left, it would hide from
# a reinstall the connections its first run should cut
rm -rf /var/db/os-portguard
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload > /dev/null 2>&1 || true
# The blocked devices' pf table, emptied when its alias is gone and no rule uses it: a table outlives
# its alias and its rules, and went on holding the addresses (2026-10-29). While the alias is still in
# Firewall: Aliases the table is OPNsense's to keep, and one a rule still uses is left as it is.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 == "portguard_blocked" && $1 !~ /r/ { print $2 }' |
while read -r table; do
    grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
    /sbin/pfctl -t "${table}" -T flush > /dev/null 2>&1 || true
done
echo "Port Guard removed; its alias stays in Firewall: Aliases"
