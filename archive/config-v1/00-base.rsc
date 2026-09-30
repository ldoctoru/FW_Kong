# 00-base.rsc  -  adopt the factory "defconf" layout (RouterOS v7)
# Verified against the device's default config:
#   WAN  = ether1 (outside the bridge)
#   LAN  = bridge "bridge": ether2-8 + sfp-sfpplus1
#   LAN  = 192.168.100.0/24, router = 192.168.100.1
#   WAN  = dynamic address from the ISP via DHCP client on ether1
#
# Nothing to create here; only guard that the lists exist, then set DNS.

:if ([:len [/interface list find name=WAN]] = 0) do={ /interface list add name=WAN }
:if ([:len [/interface list find name=LAN]] = 0) do={ /interface list add name=LAN }
:if ([:len [/interface list member find list=WAN interface=ether1]] = 0) do={ /interface list member add list=WAN interface=ether1 }
:if ([:len [/interface list member find list=LAN interface=bridge]] = 0) do={ /interface list member add list=LAN interface=bridge }

# DNS: Technitium server at 192.168.100.150 (web UI http://192.168.100.150:5380).
# Clients get it straight from DHCP; the router itself also resolves through it.
# If Technitium is down, LAN name resolution stops - keep it on a stable host.
/ip dns set servers=192.168.100.150 allow-remote-requests=no
/ip dhcp-client set [find interface=ether1] use-peer-dns=no
/ip dhcp-server network set [find address=192.168.100.0/24] dns-server=192.168.100.150

# MikroTik Cloud DDNS (dynamic WAN IP -> <serial>.sn.mynetname.net) + cloud time update.
# Show the name with:  /ip cloud print
/ip cloud set ddns-enabled=yes update-time=yes
