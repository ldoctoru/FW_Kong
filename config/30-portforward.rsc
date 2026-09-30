# 30-portforward.rsc  -  dstnat rules (WAN IP is dynamic -> match on interface list)
# Media/qbit host = 192.168.100.200, PS5 = 192.168.100.148. Re-runnable: rules are removed by comment first.

/ip firewall nat
remove [find comment="HAIRPIN NAT"]
remove [find where chain=dstnat and comment~"^(emby/jellyfin|qbit|PS5|wg)$"]

# Hairpin: LAN clients reaching a forward via the public IP
add chain=srcnat action=masquerade src-address=192.168.100.0/24 dst-address=192.168.100.0/24 out-interface-list=LAN comment="HAIRPIN NAT"

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8096-8097 to-addresses=192.168.100.200 comment="emby/jellyfin"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=58946     to-addresses=192.168.100.200 comment="qbit"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=8572      to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9302      to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9295-9308 to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=987       to-addresses=192.168.100.148 comment="PS5"
