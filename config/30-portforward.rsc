# 30-portforward.rsc  -  dstnat rules (WAN IP is dynamic -> match on interface list)
# Media/qbit host = 192.168.100.200, PS5 = 192.168.100.148. Re-runnable: rules are removed by comment first.

/ip firewall nat
remove [find comment="HAIRPIN NAT"]
remove [find where chain=dstnat and comment~"^(emby/jellyfin|qbit|PS5|wg|LAN emby/jellyfin|LAN qbit)"]
# Old hand-made rule (typo in name, no in-interface filter): superseded by the LAN rules below.
remove [find where chain=dstnat and comment="emby/jelyfin"]

# Hairpin: LAN clients reaching a forward via the public IP / DDNS name.
# Works with the two LAN-side dst-nat rules further down (masquerades the return path).
add chain=srcnat action=masquerade src-address=192.168.100.0/24 dst-address=192.168.100.0/24 out-interface-list=LAN comment="HAIRPIN NAT"

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8096-8097 to-addresses=192.168.100.200 comment="emby/jellyfin"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=58946     to-addresses=192.168.100.200 comment="qbit"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=58946     to-addresses=192.168.100.200 comment="qbit udp"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=8572      to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9302      to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9295-9308 to-addresses=192.168.100.148 comment="PS5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=987       to-addresses=192.168.100.148 comment="PS5"

# LAN-side hairpin: LAN clients using the public IP / DDNS name (dst-address-type=local
# = any address of this router, so it follows the dynamic WAN IP). PS5 needs none.
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=tcp dst-port=8096-8097 to-addresses=192.168.100.200 comment="LAN emby/jellyfin"
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=tcp dst-port=58946     to-addresses=192.168.100.200 comment="LAN qbit"
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=udp dst-port=58946     to-addresses=192.168.100.200 comment="LAN qbit udp"
