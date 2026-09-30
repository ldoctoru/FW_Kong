# 99-verify.rsc  -  READ-ONLY health check for the FW_Kong config (RouterOS v7)
# Changes nothing. Run after importing 00..30:
#   /import file-name=99-verify.rsc
# Prints OK / FAIL per check. Uses :global (not :local) on purpose: /import runs
# each top-level line as its own statement, so :local variables do not persist.
# catches duplicate rules by count, and ends with a summary.

:global vfail 0
:global vok 0

:put "=== interface lists ==="
:if ([:len [/interface list member find where list=WAN and interface=ether1]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "WAN list has ether1 once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "WAN list has ether1 once" . "  ->  " . "check /interface list member") }
:if ([:len [/interface list member find where list=LAN and interface=bridge]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "LAN list has bridge once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "LAN list has bridge once" . "  ->  " . "check /interface list member") }
:if ([:len [/ip dhcp-client find where interface=ether1]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "one DHCP client on ether1") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "one DHCP client on ether1" . "  ->  " . "check /ip dhcp-client") }

:put "=== firewall filter: expected rules exist exactly once ==="
:if ([:len [/ip firewall filter find comment="in: est/rel"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: est/rel") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: est/rel" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="in: drop invalid"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: drop invalid") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: drop invalid" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="in: icmp (rate limited)"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: icmp (rate limited)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: icmp (rate limited)" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="in: LAN full access to router"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: LAN full access to router") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: LAN full access to router" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="in: log WAN drops"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: log WAN drops") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: log WAN drops" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="in: drop all else"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in: drop all else") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in: drop all else" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: fasttrack"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: fasttrack") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: fasttrack" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: est/rel"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: est/rel") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: est/rel" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: drop invalid"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: drop invalid") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: drop invalid" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: drop WAN new not DSTNATed"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: drop WAN new not DSTNATed") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: drop WAN new not DSTNATed" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: allow port-forwards (30-portforward.rsc)"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: allow port-forwards (30-portforward.rsc)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: allow port-forwards (30-portforward.rsc)" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: LAN <-> LAN (incl. hairpin)"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: LAN <-> LAN (incl. hairpin)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: LAN <-> LAN (incl. hairpin)" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: bogon src from LAN"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: bogon src from LAN") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: bogon src from LAN" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: LAN -> WAN"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: LAN -> WAN") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: LAN -> WAN" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fwd: drop all else"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd: drop all else") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd: drop all else" . "  ->  " . "expected exactly 1") }

:put "=== firewall filter: duplicates and leftovers ==="
:global filterTotal [:len [/ip firewall filter find dynamic=no]]
:if ($filterTotal = 15) do={ :set vok ($vok + 1); :put ("OK    " . "filter has exactly 15 rules (no duplicates or extras)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter has exactly 15 rules (no duplicates or extras)" . "  ->  " . ("found " . $filterTotal . " rules")) }
:if ([:len [/ip firewall filter find comment~"defconf"]] = 0) do={ :set vok ($vok + 1); :put ("OK    " . "no factory defconf filter rules left") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "no factory defconf filter rules left" . "  ->  " . "run 10-firewall.rsc") }

:put "=== firewall filter: chain order ==="
:global lastIn
:global lastFw
:global firstFw
:global inCount 0
:global fwCount 0
:foreach rid in=[/ip firewall filter find chain=input dynamic=no] do={ :set lastIn $rid; :set inCount ($inCount + 1) }
:foreach rid in=[/ip firewall filter find chain=forward dynamic=no] do={
  :if ($fwCount = 0) do={ :set firstFw $rid }
  :set lastFw $rid
  :set fwCount ($fwCount + 1)
}
:if ($inCount > 0 and $fwCount > 0) do={ :set vok ($vok + 1); :put ("OK    " . "input and forward chains have rules") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "input and forward chains have rules" . "  ->  " . "chain empty") }
:if ($inCount > 0 and $fwCount > 0) do={
:if ([/ip firewall filter get $lastIn action] = "drop") do={ :set vok ($vok + 1); :put ("OK    " . "input chain ends with drop") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "input chain ends with drop" . "  ->  " . "last input rule is not a drop") }
:if ([/ip firewall filter get $lastFw action] = "drop") do={ :set vok ($vok + 1); :put ("OK    " . "forward chain ends with drop") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "forward chain ends with drop" . "  ->  " . "last forward rule is not a drop") }
:if ([/ip firewall filter get $firstFw action] = "fasttrack-connection") do={ :set vok ($vok + 1); :put ("OK    " . "forward chain starts with fasttrack") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "forward chain starts with fasttrack" . "  ->  " . "first forward rule is not fasttrack") }
}

:put "=== NAT ==="
:if ([:len [/ip firewall nat find comment="NAT: LAN -> WAN"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "WAN masquerade exactly once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "WAN masquerade exactly once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="HAIRPIN NAT"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "hairpin rule exactly once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "hairpin rule exactly once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="emby/jellyfin"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "emby/jellyfin forward once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "emby/jellyfin forward once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="qbit"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "qbit forward once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "qbit forward once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="LAN emby/jellyfin"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "LAN hairpin emby/jellyfin once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "LAN hairpin emby/jellyfin once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="LAN qbit"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "LAN hairpin qbit once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "LAN hairpin qbit once" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="PS5"]] = 4) do={ :set vok ($vok + 1); :put ("OK    " . "PS5 forwards = 4 rules") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "PS5 forwards = 4 rules" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment~"defconf"]] = 0) do={ :set vok ($vok + 1); :put ("OK    " . "no factory defconf NAT rules left") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "no factory defconf NAT rules left" . "  ->  " . "run 10-firewall.rsc") }
:if ([:len [/ip firewall nat find comment="wg"]] = 0) do={ :set vok ($vok + 1); :put ("OK    " . "old wg forward removed") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "old wg forward removed" . "  ->  " . "run 30-portforward.rsc") }
:global natTotal [:len [/ip firewall nat find]]
:if ($natTotal = 10) do={ :set vok ($vok + 1); :put ("OK    " . "NAT has exactly 10 rules (no duplicates or extras)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "NAT has exactly 10 rules (no duplicates or extras)" . "  ->  " . ("found " . $natTotal . " rules")) }
:global dstTotal [:len [/ip firewall nat find chain=dstnat]]
:if ($dstTotal = 8) do={ :set vok ($vok + 1); :put ("OK    " . "exactly 8 port-forward (dstnat) rules") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "exactly 8 port-forward (dstnat) rules" . "  ->  " . ("found " . $dstTotal)) }
:global nasBad 0
:foreach rid in=[/ip firewall nat find comment="emby/jellyfin"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
:foreach rid in=[/ip firewall nat find comment="LAN emby/jellyfin"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
:foreach rid in=[/ip firewall nat find comment="LAN qbit"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
:foreach rid in=[/ip firewall nat find comment="qbit"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
:if ($nasBad = 0) do={ :set vok ($vok + 1); :put ("OK    " . "emby/jellyfin/qbit -> 192.168.100.200") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "emby/jellyfin/qbit -> 192.168.100.200" . "  ->  " . ($nasBad . " rule(s) point elsewhere")) }
:global ps5Bad 0
:foreach rid in=[/ip firewall nat find comment="PS5"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.148") do={ :set ps5Bad ($ps5Bad + 1) }
}
:if ($ps5Bad = 0) do={ :set vok ($vok + 1); :put ("OK    " . "PS5 -> 192.168.100.148") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "PS5 -> 192.168.100.148" . "  ->  " . ($ps5Bad . " rule(s) point elsewhere")) }

:put "=== address list ==="
:global bogons [:len [/ip firewall address-list find list=bogons]]
:if ($bogons = 5) do={ :set vok ($vok + 1); :put ("OK    " . "bogons list has 5 entries (no duplicates)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "bogons list has 5 entries (no duplicates)" . "  ->  " . ("found " . $bogons)) }

:put "=== DNS / DHCP ==="
:if ([:tostr [/ip dns get servers]] = "192.168.100.150") do={ :set vok ($vok + 1); :put ("OK    " . "router DNS = Technitium 192.168.100.150") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "router DNS = Technitium 192.168.100.150" . "  ->  " . [:tostr [/ip dns get servers]]) }
:if ([:tostr [/ip dns get allow-remote-requests]] = "false") do={ :set vok ($vok + 1); :put ("OK    " . "router does not serve DNS to LAN") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "router does not serve DNS to LAN" . "  ->  " . "allow-remote-requests is on") }
:if ([:tostr [/ip dhcp-server network get [find where address="192.168.100.0/24"] dns-server]] = "192.168.100.150") do={ :set vok ($vok + 1); :put ("OK    " . "DHCP hands out Technitium") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "DHCP hands out Technitium" . "  ->  " . "check /ip dhcp-server network") }
:if ([:tostr [/ip dhcp-client get [find where interface=ether1] use-peer-dns]] = "false") do={ :set vok ($vok + 1); :put ("OK    " . "ISP DNS ignored") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "ISP DNS ignored" . "  ->  " . "use-peer-dns is on") }

:put "=== hardening ==="
:if ([:tostr [/ip service get telnet disabled]] = "true") do={ :set vok ($vok + 1); :put ("OK    " . "service disabled: telnet") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "service disabled: telnet" . "  ->  " . "still enabled") }
:if ([:tostr [/ip service get ftp disabled]] = "true") do={ :set vok ($vok + 1); :put ("OK    " . "service disabled: ftp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "service disabled: ftp" . "  ->  " . "still enabled") }
:if ([:tostr [/ip service get www disabled]] = "true") do={ :set vok ($vok + 1); :put ("OK    " . "service disabled: www") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "service disabled: www" . "  ->  " . "still enabled") }
:if ([:tostr [/ip service get api disabled]] = "true") do={ :set vok ($vok + 1); :put ("OK    " . "service disabled: api") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "service disabled: api" . "  ->  " . "still enabled") }
:if ([:tostr [/ip service get api-ssl disabled]] = "true") do={ :set vok ($vok + 1); :put ("OK    " . "service disabled: api-ssl") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "service disabled: api-ssl" . "  ->  " . "still enabled") }
:if ([:tostr [/ip upnp get enabled]] = "false") do={ :set vok ($vok + 1); :put ("OK    " . "UPnP off") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "UPnP off" . "  ->  " . "enabled") }
:if ([:tostr [/ip proxy get enabled]] = "false") do={ :set vok ($vok + 1); :put ("OK    " . "web proxy off") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "web proxy off" . "  ->  " . "enabled") }
:if ([:tostr [/ip socks get enabled]] = "false") do={ :set vok ($vok + 1); :put ("OK    " . "SOCKS off") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "SOCKS off" . "  ->  " . "enabled") }

:put "=== cloud ==="
:global ddns [:tostr [/ip cloud get ddns-enabled]]
:if ($ddns = "true" or $ddns = "yes") do={ :set vok ($vok + 1); :put ("OK    " . "cloud DDNS enabled") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "cloud DDNS enabled" . "  ->  " . ("ddns-enabled=" . $ddns)) }
:put ("      DDNS name: " . [/ip cloud get dns-name])

:put "==============================="
:put ("passed: " . $vok . "   failed: " . $vfail)
:if ($vfail = 0) do={ :put "RESULT: ALL OK" } else={ :put "RESULT: FIX THE FAIL LINES ABOVE" }
