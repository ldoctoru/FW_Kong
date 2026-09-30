# firewall.rsc  -  simple default-deny firewall for a homelab (RouterOS v7)
#
# Network assumed:  WAN = ether1 (dynamic IP from ISP)
#                   LAN = "bridge", 192.168.100.0/24, router 192.168.100.1
#
# WARNING: starts from scratch. It REMOVES every existing (non-dynamic) firewall
# filter and NAT rule first. Take a backup, use Safe Mode, import from a LAN port.
# Re-runnable: running it again gives the same result, no duplicates.

# --- interface lists the rules use (created only if missing) ---
:if ([:len [/interface list find name=WAN]] = 0) do={ /interface list add name=WAN }
:if ([:len [/interface list find name=LAN]] = 0) do={ /interface list add name=LAN }
:if ([:len [/interface list member find list=WAN interface=ether1]] = 0) do={ /interface list member add list=WAN interface=ether1 }
:if ([:len [/interface list member find list=LAN interface=bridge]] = 0) do={ /interface list member add list=LAN interface=bridge }

# --- start from scratch ---
/ip firewall filter remove [find dynamic=no]
/ip firewall nat remove [find dynamic=no]
/ip firewall address-list remove [find list=bogons]

# --- filter: 10 rules ---
/ip firewall filter
# traffic TO the router
add chain=input action=accept connection-state=established,related,untracked comment="fw: in est/rel"
add chain=input action=drop connection-state=invalid comment="fw: in drop invalid"
add chain=input action=accept protocol=icmp comment="fw: in icmp"
add chain=input action=accept in-interface-list=LAN comment="fw: in LAN"
# record (no log spam) who probes management ports from the internet; see: /ip firewall address-list print where list=wan-mgmt-attempts
add chain=input action=add-src-to-address-list address-list=wan-mgmt-attempts address-list-timeout=1d in-interface-list=WAN protocol=tcp dst-port=21,22,23,80,443,8291,8728,8729 connection-state=new comment="fw: in WAN mgmt attempts"
add chain=input action=drop comment="fw: in drop all else"
# traffic THROUGH the router (LAN -> WAN is allowed by default)
add chain=forward action=fasttrack-connection connection-state=established,related comment="fw: fwd fasttrack"
add chain=forward action=accept connection-state=established,related,untracked comment="fw: fwd est/rel"
add chain=forward action=drop connection-state=invalid comment="fw: fwd drop invalid"
add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="fw: fwd drop WAN not dstnat"

# --- NAT: internet access + port forwards (WAN IP is dynamic, so match the WAN list) ---
/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN comment="fw: masquerade WAN"
add chain=srcnat action=masquerade src-address=192.168.100.0/24 dst-address=192.168.100.0/24 out-interface-list=LAN comment="fw: hairpin masquerade"

# from the internet -> media server 192.168.100.200 and PS5 192.168.100.148
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8096-8097 to-addresses=192.168.100.200 comment="fw: emby"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=58946 to-addresses=192.168.100.200 comment="fw: qbit tcp"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=58946 to-addresses=192.168.100.200 comment="fw: qbit udp"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=8572 to-addresses=192.168.100.148 comment="fw: ps5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9302 to-addresses=192.168.100.148 comment="fw: ps5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=9295-9308 to-addresses=192.168.100.148 comment="fw: ps5"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=987 to-addresses=192.168.100.148 comment="fw: ps5"

# from the LAN using the public IP / DDNS name (dst-address-type=local = the router's own addresses)
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=tcp dst-port=8096-8097 to-addresses=192.168.100.200 comment="fw: LAN emby"
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=tcp dst-port=58946 to-addresses=192.168.100.200 comment="fw: LAN qbit tcp"
add chain=dstnat action=dst-nat in-interface-list=LAN dst-address-type=local protocol=udp dst-port=58946 to-addresses=192.168.100.200 comment="fw: LAN qbit udp"
