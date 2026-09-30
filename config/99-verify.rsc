# 99-verify.rsc  -  READ-ONLY health check for the FW_Kong config (RouterOS v7)
# Changes nothing. Run after importing 00..30:
#   /import file-name=99-verify.rsc
# Prints OK / FAIL per check, finds duplicate rules, and ends with a summary.

:global vfail 0
:global vok 0

:local chk do={
  :global vfail
  :global vok
  :if ($ok) do={
    :set vok ($vok + 1)
    :put ("OK    " . $name)
  } else={
    :set vfail ($vfail + 1)
    :put ("FAIL  " . $name . "  ->  " . $info)
  }
}

:put "=== interface lists ==="
$chk ok=([:len [/interface list member find where list=WAN and interface=ether1]] = 1) name="WAN list has ether1 once" info="check /interface list member"
$chk ok=([:len [/interface list member find where list=LAN and interface=bridge]] = 1) name="LAN list has bridge once" info="check /interface list member"
$chk ok=([:len [/ip dhcp-client find where interface=ether1]] = 1) name="one DHCP client on ether1" info="check /ip dhcp-client"

:put "=== firewall filter: expected rules exist exactly once ==="
:local filterComments {"in: est/rel";"in: drop invalid";"in: icmp (rate limited)";"in: LAN full access to router";"in: log WAN drops";"in: drop all else";"fwd: fasttrack";"fwd: est/rel";"fwd: drop invalid";"fwd: drop WAN new not DSTNATed";"fwd: allow port-forwards (30-portforward.rsc)";"fwd: LAN <-> LAN (incl. hairpin)";"fwd: bogon src from LAN";"fwd: LAN -> WAN";"fwd: drop all else"}
:foreach c in=$filterComments do={
  :local n [:len [/ip firewall filter find where comment=$c]]
  $chk ok=($n = 1) name=("filter: " . $c) info=("found " . $n . " (want 1)")
}

:put "=== firewall filter: duplicates and leftovers ==="
:local seen [:toarray ""]
:local dupes 0
:foreach i in=[/ip firewall filter find where comment!=""] do={
  :local k [/ip firewall filter get $i comment]
  :if ([:typeof ($seen->$k)] != "nothing") do={
    :set dupes ($dupes + 1)
    :put ("      duplicate filter comment: " . $k)
  } else={ :set ($seen->$k) 1 }
}
$chk ok=($dupes = 0) name="no duplicate filter rules" info=($dupes . " duplicate comment(s)")
$chk ok=([:len [/ip firewall filter find where comment~"defconf"]] = 0) name="no factory defconf filter rules left" info="run 10-firewall.rsc"
$chk ok=([:len [/ip firewall filter find where comment=""]] = 0) name="no uncommented filter rules" info="unknown rule present"

:put "=== firewall filter: chain order ==="
:local inIds [/ip firewall filter find where chain=input]
:local fwIds [/ip firewall filter find where chain=forward]
:local lastIn [:pick $inIds ([:len $inIds] - 1)]
:local lastFw [:pick $fwIds ([:len $fwIds] - 1)]
$chk ok=([/ip firewall filter get $lastIn action] = "drop") name="input chain ends with drop" info="last input rule is not a drop"
$chk ok=([/ip firewall filter get $lastFw action] = "drop") name="forward chain ends with drop" info="last forward rule is not a drop"
$chk ok=([/ip firewall filter get [:pick $fwIds 0] action] = "fasttrack-connection") name="forward chain starts with fasttrack" info="first forward rule is not fasttrack"

:put "=== NAT ==="
$chk ok=([:len [/ip firewall nat find where comment="NAT: LAN -> WAN"]] = 1) name="WAN masquerade exactly once" info="check /ip firewall nat"
$chk ok=([:len [/ip firewall nat find where comment="HAIRPIN NAT"]] = 1) name="hairpin rule exactly once" info="check /ip firewall nat"
$chk ok=([:len [/ip firewall nat find where comment="emby/jellyfin"]] = 1) name="emby/jellyfin forward once" info="check /ip firewall nat"
$chk ok=([:len [/ip firewall nat find where comment="qbit"]] = 1) name="qbit forward once" info="check /ip firewall nat"
$chk ok=([:len [/ip firewall nat find where comment="PS5"]] = 4) name="PS5 forwards = 4 rules" info="check /ip firewall nat"
$chk ok=([:len [/ip firewall nat find where comment~"defconf"]] = 0) name="no factory defconf NAT rules left" info="run 10-firewall.rsc"
$chk ok=([:len [/ip firewall nat find where comment="wg"]] = 0) name="old wg forward removed" info="run 30-portforward.rsc"

:local natSeen [:toarray ""]
:local natDupes 0
:foreach i in=[/ip firewall nat find where chain=dstnat] do={
  :local k ([/ip firewall nat get $i protocol] . "/" . [/ip firewall nat get $i dst-port])
  :if ([:typeof ($natSeen->$k)] != "nothing") do={
    :set natDupes ($natDupes + 1)
    :put ("      duplicate dstnat: " . $k)
  } else={ :set ($natSeen->$k) 1 }
}
$chk ok=($natDupes = 0) name="no duplicate port forwards (proto/port)" info=($natDupes . " duplicate(s)")

:local nasBad 0
:foreach i in=[/ip firewall nat find where comment="emby/jellyfin" or comment="qbit"] do={
  :if ([:tostr [/ip firewall nat get $i to-addresses]] != "192.168.100.200") do={ :set nasBad ($nasBad + 1) }
}
$chk ok=($nasBad = 0) name="emby/jellyfin/qbit -> 192.168.100.200" info=($nasBad . " rule(s) point elsewhere")
:local ps5Bad 0
:foreach i in=[/ip firewall nat find where comment="PS5"] do={
  :if ([:tostr [/ip firewall nat get $i to-addresses]] != "192.168.100.148") do={ :set ps5Bad ($ps5Bad + 1) }
}
$chk ok=($ps5Bad = 0) name="PS5 -> 192.168.100.148" info=($ps5Bad . " rule(s) point elsewhere")

:put "=== address list ==="
:local bogons [:len [/ip firewall address-list find where list=bogons]]
$chk ok=($bogons = 5) name="bogons list has 5 entries (no duplicates)" info=("found " . $bogons)

:put "=== DNS / DHCP ==="
$chk ok=([:tostr [/ip dns get servers]] = "192.168.100.150") name="router DNS = Technitium 192.168.100.150" info=[:tostr [/ip dns get servers]]
$chk ok=([/ip dns get allow-remote-requests] = false) name="router does not serve DNS to LAN" info="allow-remote-requests is on"
$chk ok=([:tostr [/ip dhcp-server network get [find where address="192.168.100.0/24"] dns-server]] = "192.168.100.150") name="DHCP hands out Technitium" info="check /ip dhcp-server network"
$chk ok=([/ip dhcp-client get [find where interface=ether1] use-peer-dns] = false) name="ISP DNS ignored" info="use-peer-dns is on"

:put "=== hardening ==="
:foreach s in={"telnet";"ftp";"www";"api";"api-ssl"} do={
  $chk ok=([/ip service get $s disabled] = true) name=("service disabled: " . $s) info="still enabled"
}
$chk ok=([/ip upnp get enabled] = false) name="UPnP off" info="enabled"
$chk ok=([/ip proxy get enabled] = false) name="web proxy off" info="enabled"
$chk ok=([/ip socks get enabled] = false) name="SOCKS off" info="enabled"

:put "=== cloud ==="
:local ddns [:tostr [/ip cloud get ddns-enabled]]
$chk ok=($ddns = "true" or $ddns = "yes") name="cloud DDNS enabled" info=("ddns-enabled=" . $ddns)
:put ("      DDNS name: " . [/ip cloud get dns-name])

:put "==============================="
:put ("passed: " . $vok . "   failed: " . $vfail)
:if ($vfail = 0) do={ :put "RESULT: ALL OK" } else={ :put "RESULT: FIX THE FAIL LINES ABOVE" }
