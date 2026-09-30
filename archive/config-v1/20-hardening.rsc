# 20-hardening.rsc  -  disable unused services (RouterOS v7)

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set ssh address=192.168.100.0/24
set winbox address=192.168.100.0/24

/ip neighbor discovery-settings set discover-interface-list=LAN
/tool mac-server set allowed-interface-list=LAN
/tool mac-server mac-winbox set allowed-interface-list=LAN
/ip upnp set enabled=no
/ip proxy set enabled=no
/ip socks set enabled=no
/ip ssh set strong-crypto=yes
