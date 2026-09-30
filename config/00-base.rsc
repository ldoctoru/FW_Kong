# 00-base.rsc  -  flat LAN, single WAN (RouterOS v7)
# Assumptions (edit to match): WAN = ether1 (to modem 192.168.100.1),
# LAN = ether2-ether5 in bridge "bridge-lan", LAN = 192.168.88.0/24.
# LAN must NOT overlap the modem subnet 192.168.100.0/24.

:global wanIf "ether1"

/interface bridge add name=bridge-lan comment="LAN"
/interface bridge port
add bridge=bridge-lan interface=ether2
add bridge=bridge-lan interface=ether3
add bridge=bridge-lan interface=ether4
add bridge=bridge-lan interface=ether5

/interface list add name=WAN
/interface list add name=LAN
/interface list member add list=WAN interface=ether1
/interface list member add list=LAN interface=bridge-lan

/ip address add address=192.168.88.1/24 interface=bridge-lan comment="LAN gateway"

# WAN gets its address from the modem (192.168.100.0/24, gw 192.168.100.1).
# Static alternative:
#   /ip address add address=192.168.100.2/24 interface=ether1
#   /ip route add gateway=192.168.100.1
/ip dhcp-client add interface=ether1 use-peer-dns=no add-default-route=yes comment="WAN"

/ip pool add name=lan-pool ranges=192.168.88.100-192.168.88.199
/ip dhcp-server add name=lan-dhcp interface=bridge-lan address-pool=lan-pool lease-time=1d
/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=192.168.88.1

/ip dns set allow-remote-requests=yes servers=1.1.1.1,9.9.9.9
