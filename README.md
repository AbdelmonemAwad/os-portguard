# Port Guard for OPNsense

Layer 2 rules for the ports of the firewall: a device allowed or blocked inside the network by its MAC address or by the type of frame it sends, before the IP rules see it - and, on a Sophos XGS, in its switch where the switch can enforce them.

> **Planned - nothing here runs yet.** This repository was opened on 2026-10-22 to hold
> Port Guard as a plugin of its own. No code has been written or moved into it, and there is no
> release.

## What it is to do

- rules by MAC address and by frame type, written as pf's Ethernet rules;
- on a Sophos XGS, the rules the 88E6193X switch can hold, kept in the switch, so a blocked device is stopped at the port;
- a page in the XGS section of OPNsense's menu.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
