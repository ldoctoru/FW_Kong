# 10-firewall.rsc  -  default-deny, stateful (RouterOS v7)
# Requires interface lists WAN / LAN from 00-base.rsc.

/ip firewall address-list
add list=bogons address=0.0.0.0/8
add list=bogons address=127.0.0.0/8
add list=bogons address=169.254.0.0/16
add list=bogons address=224.0.0.0/4
add list=bogons address=240.0.0.0/4
# NOTE: 192.168.100.0/24 (modem) is private but is our upstream; not listed.

# Replace the factory rules with ours (safe to re-run: our rules carry no "defconf").
/ip firewall filter remove [find comment~"defconf"]
/ip firewall nat remove [find comment~"defconf"]

/ip firewall filter
# ---- INPUT (to the router) ----
add chain=input action=accept connection-state=established,related,untracked comment="in: est/rel"
add chain=input action=drop   connection-state=invalid comment="in: drop invalid"
add chain=input action=accept protocol=icmp limit=20,5:packet comment="in: icmp (rate limited)"
add chain=input action=accept in-interface-list=LAN comment="in: LAN full access to router"
add chain=input action=drop   in-interface-list=WAN log=yes log-prefix="WAN-IN-DROP " limit=5,5:packet comment="in: log WAN drops"
add chain=input action=drop   comment="in: drop all else"

# ---- FORWARD (through the router) ----
add chain=forward action=fasttrack-connection hw-offload=yes connection-state=established,related comment="fwd: fasttrack"
add chain=forward action=accept connection-state=established,related,untracked comment="fwd: est/rel"
add chain=forward action=drop   connection-state=invalid comment="fwd: drop invalid"
add chain=forward action=drop   connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="fwd: drop WAN new not DSTNATed"
add chain=forward action=drop   in-interface-list=LAN src-address-list=bogons comment="fwd: bogon src from LAN"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="fwd: LAN -> WAN"
add chain=forward action=drop   comment="fwd: drop all else"

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN comment="NAT: LAN -> WAN (also reaches modem UI 192.168.100.1)"
# Example port forward (disabled):
# add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=8443 to-addresses=192.168.88.10 to-ports=443 disabled=yes
