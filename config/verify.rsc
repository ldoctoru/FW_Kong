# verify.rsc  -  READ-ONLY check of firewall.rsc (RouterOS v7). Changes nothing.
#   /import file-name=verify.rsc
# Plain inline checks with :global variables on purpose: /import runs each top-level
# line as its own statement, so :local variables and helper functions do not work.

:global vfail 0
:global vok 0

:put "=== interface lists ==="
:if ([:len [/interface list member find where list=WAN and interface=ether1]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "WAN list has ether1 once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "WAN list has ether1 once" . "  ->  " . "see /ip firewall") }
:if ([:len [/interface list member find where list=LAN and interface=bridge]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "LAN list has bridge once") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "LAN list has bridge once" . "  ->  " . "see /ip firewall") }

:put "=== filter (10 rules) ==="
:if ([:len [/ip firewall filter find comment="fw: in est/rel"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in est/rel") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in est/rel" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: in drop invalid"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in drop invalid") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in drop invalid" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: in icmp"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in icmp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in icmp" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: in LAN"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in LAN") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in LAN" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: in WAN mgmt attempts"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in WAN mgmt attempts") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in WAN mgmt attempts" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: in drop all else"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: in drop all else") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: in drop all else" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: fwd fasttrack"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd fasttrack") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd fasttrack" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: fwd est/rel"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd est/rel") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd est/rel" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: fwd drop invalid"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd drop invalid") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd drop invalid" . "  ->  " . "expected exactly 1") }
:if ([:len [/ip firewall filter find comment="fw: fwd drop WAN not dstnat"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "filter: fwd drop WAN not dstnat") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter: fwd drop WAN not dstnat" . "  ->  " . "expected exactly 1") }
:global filterTotal [:len [/ip firewall filter find dynamic=no]]
:if ($filterTotal = 10) do={ :set vok ($vok + 1); :put ("OK    " . "filter has exactly 10 rules (no duplicates or extras)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "filter has exactly 10 rules (no duplicates or extras)" . "  ->  " . ("found " . $filterTotal)) }
:global lastIn
:global firstFw
:global inCount 0
:global fwCount 0
:foreach rid in=[/ip firewall filter find chain=input dynamic=no] do={ :set lastIn $rid; :set inCount ($inCount + 1) }
:foreach rid in=[/ip firewall filter find chain=forward dynamic=no] do={
  :if ($fwCount = 0) do={ :set firstFw $rid }
  :set fwCount ($fwCount + 1)
}
:if ($inCount > 0 and $fwCount > 0) do={ :set vok ($vok + 1); :put ("OK    " . "input and forward chains have rules") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "input and forward chains have rules" . "  ->  " . "chain empty") }
:if ($inCount > 0 and $fwCount > 0) do={
:if ([/ip firewall filter get $lastIn action] = "drop") do={ :set vok ($vok + 1); :put ("OK    " . "input chain ends with drop") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "input chain ends with drop" . "  ->  " . "last input rule is not a drop") }
:if ([/ip firewall filter get $firstFw action] = "fasttrack-connection") do={ :set vok ($vok + 1); :put ("OK    " . "forward chain starts with fasttrack") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "forward chain starts with fasttrack" . "  ->  " . "first forward rule is not fasttrack") }
}

:put "=== NAT (12 rules) ==="
:if ([:len [/ip firewall nat find comment="fw: masquerade WAN"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: masquerade WAN") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: masquerade WAN" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: hairpin masquerade"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: hairpin masquerade") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: hairpin masquerade" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: emby"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: emby") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: emby" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: qbit tcp"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: qbit tcp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: qbit tcp" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: qbit udp"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: qbit udp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: qbit udp" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: ps5"]] = 4) do={ :set vok ($vok + 1); :put ("OK    " . "nat: ps5 (x4)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: ps5 (x4)" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: LAN emby"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: LAN emby") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: LAN emby" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: LAN qbit tcp"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: LAN qbit tcp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: LAN qbit tcp" . "  ->  " . "check /ip firewall nat") }
:if ([:len [/ip firewall nat find comment="fw: LAN qbit udp"]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "nat: LAN qbit udp") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "nat: LAN qbit udp" . "  ->  " . "check /ip firewall nat") }
:global natTotal [:len [/ip firewall nat find dynamic=no]]
:if ($natTotal = 12) do={ :set vok ($vok + 1); :put ("OK    " . "NAT has exactly 12 rules (no duplicates or extras)") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "NAT has exactly 12 rules (no duplicates or extras)" . "  ->  " . ("found " . $natTotal)) }
:global dstTotal [:len [/ip firewall nat find chain=dstnat]]
:if ($dstTotal = 10) do={ :set vok ($vok + 1); :put ("OK    " . "exactly 10 port-forward (dstnat) rules") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "exactly 10 port-forward (dstnat) rules" . "  ->  " . ("found " . $dstTotal)) }
:global nasBad 0
:foreach rid in=[/ip firewall nat find comment~"^fw: (emby|qbit|LAN emby|LAN qbit)"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
:if ($nasBad = 0) do={ :set vok ($vok + 1); :put ("OK    " . "emby/qbit forwards -> 192.168.100.200") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "emby/qbit forwards -> 192.168.100.200" . "  ->  " . ($nasBad . " rule(s) point elsewhere")) }
:global ps5Bad 0
:foreach rid in=[/ip firewall nat find comment="fw: ps5"] do={
  :if ([:tostr [/ip firewall nat get $rid to-addresses]] != "192.168.100.148") do={ :set ps5Bad ($ps5Bad + 1) }
}
:if ($ps5Bad = 0) do={ :set vok ($vok + 1); :put ("OK    " . "ps5 forwards -> 192.168.100.148") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "ps5 forwards -> 192.168.100.148" . "  ->  " . ($ps5Bad . " rule(s) point elsewhere")) }

:put "=== logging ==="
:if ([:len [/system logging action find name=authlog]] = 1) do={ :set vok ($vok + 1); :put ("OK    " . "log action authlog exists") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "log action authlog exists" . "  ->  " . "run logging.rsc") }
:if ([:len [/system logging find action=authlog]] = 2) do={ :set vok ($vok + 1); :put ("OK    " . "2 log rules use authlog") } else={ :set vfail ($vfail + 1); :put ("FAIL  " . "2 log rules use authlog" . "  ->  " . "run logging.rsc") }

:put "==============================="
:put ("passed: " . $vok . "   failed: " . $vfail)
:if ($vfail = 0) do={ :put "RESULT: ALL OK" } else={ :put "RESULT: FIX THE FAIL LINES ABOVE" }
