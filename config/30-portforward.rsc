# 30-portforward.rsc  -  dstnat rules (WAN IP is dynamic -> match on interface list)
# EDIT the :local addresses below BEFORE importing (targets were not visible
# in the Winbox screenshot). Re-runnable: rules are removed by comment first.

:local nasHost   "192.168.100.X"   ; # emby/jellyfin + qbittorrent host
:local ps5Host   "192.168.100.X"   ; # PS5
:local waHost    "192.168.100.X"   ; # whatsapp service host
:local wgHost    "192.168.100.X"   ; # wireguard host

/ip firewall nat
remove [find comment="HAIRPIN NAT"]
remove [find where chain=dstnat and comment~"^(emby/jellyfin|qbit|PS5|whastapp|wg)$"]

# Hairpin: LAN clients reaching a forward via the public IP
add chain=srcnat action=masquerade src-address=192.168.100.0/24 dst-address=192.168.100.0/24 out-interface-list=LAN comment="HAIRPIN NAT" place-before=0

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8096-8097 to-addresses=$nasHost comment="emby/jellyfin"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=58946     to-addresses=$nasHost comment="qbit"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=8572      to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9302      to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9295-9308 to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=987       to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=3000-3006 to-addresses=$waHost  comment="whastapp"
# WireGuard normally uses UDP; the live rule is tcp/13231 - verify, then fix protocol.
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=13231     to-addresses=$wgHost  comment="wg"
