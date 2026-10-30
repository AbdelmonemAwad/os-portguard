#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-portguard have been removed; not during an upgrade. The rules
# hook is gone with them, so a filter reload takes the rules out of pf. Kept: the settings, and the
# portguard_blocked alias, which blocks nothing without the rules - remove it in Firewall: Aliases, or
# turn Port Guard off and Apply before removing it, which removes it and empties its table.

# A cut already running stops now, rather than after its files went (2026-10-29). The bracket keeps
# the pattern from matching the shell that runs this text.
/bin/pkill -f '/usr/local/opnsense/scripts/[p]ortguard/' 2> /dev/null || true

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-portguard > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the
# model's directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard/Menu /usr/local/opnsense/mvc/app/models/OPNsense/PortGuard 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml

# Nor is what cut.py kept, the table's last reading: left, it would hide from a reinstall the
# connections its first run should cut. Nor what Python compiled beside the scripts - 1.0.0's
# installer compiled them where they are, and a self-update over a package runs the installer -
# which kept their directory; the directories go once empty.
rm -rf /var/db/os-portguard /usr/local/opnsense/scripts/portguard/__pycache__
[ -d /usr/local/opnsense/scripts/portguard ] &&
    find /usr/local/opnsense/scripts/portguard -depth -type d -empty -delete 2> /dev/null

[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload > /dev/null 2>&1 || true

# The blocked devices' pf table, emptied when its alias is gone and no rule uses it: a table outlives
# its alias and its rules, and went on holding the addresses (2026-10-29). While the alias is still in
# Firewall: Aliases the table is OPNsense's to keep, and one a rule still uses is left as it is.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 == "portguard_blocked" && $1 !~ /r/ { print $2 }' |
while read -r table; do
	grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
	/sbin/pfctl -t "${table}" -T flush > /dev/null 2>&1 || true
done

echo "Port Guard removed; its alias stays in Firewall: Aliases"
