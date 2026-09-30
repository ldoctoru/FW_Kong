# 30-portforward.rsc  -  dstnat rules (WAN IP is dynamic -> match on interface list)
# Targets taken from the live router. Re-runnable: rules are removed by comment first.

:local nasHost   "192.168.100.200"   ; # emby/jellyfin + qbittorrent host
:local ps5Host   "192.168.100.148"   ; # PS5

/ip firewall nat
remove [find comment="HAIRPIN NAT"]
remove [find where chain=dstnat and comment~"^(emby/jellyfin|qbit|PS5|wg)$"]

# Hairpin: LAN clients reaching a forward via the public IP
add chain=srcnat action=masquerade src-address=192.168.100.0/24 dst-address=192.168.100.0/24 out-interface-list=LAN comment="HAIRPIN NAT"

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8096-8097 to-addresses=$nasHost comment="emby/jellyfin"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=58946     to-addresses=$nasHost comment="qbit"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=8572      to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9302      to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9295-9308 to-addresses=$ps5Host comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=987       to-addresses=$ps5Host comment="PS5"
