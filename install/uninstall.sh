#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Port Guard plugin files. The rules go with the filter reload run here, because they are
# registered by the hook removed below. Kept: the settings, and the portguard_blocked alias in
# Firewall: Aliases, which blocks nothing without the rules - remove it there when no longer wanted.

# the rules hook first, which would stop a filter reload if it outlived its model
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
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload > /dev/null 2>&1 || true
echo "Port Guard removed; its alias stays in Firewall: Aliases"
