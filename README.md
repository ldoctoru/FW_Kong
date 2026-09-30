# FW_Kong - simple MikroTik homelab firewall

One small RouterOS v7 script: a default-deny firewall for a flat home network.
The earlier, larger version (DNS, hardening, DDNS, verify) is kept in [`archive/`](archive/).

## Network assumed

| Item   | Value                                                        |
|--------|--------------------------------------------------------------|
| WAN    | `ether1`, dynamic IP from the ISP                            |
| LAN    | `bridge` (`ether2-8`, `sfp-sfpplus1`), `192.168.100.0/24`    |
| Router | `192.168.100.1`                                              |

## Files

| File                  | What it does                                              |
|-----------------------|-----------------------------------------------------------|
| `config/firewall.rsc` | The whole firewall: 10 filter rules, 12 NAT rules         |
| `config/logging.rsc`  | Separate log buffer for logins and failed logins          |
| `config/verify.rsc`   | Read-only check that the router matches `firewall.rsc`    |
| `archive/`            | Previous config and README (not used, kept for reference) |

## The rules

**Filter (10 rules, all commented `fw: ...`)**

| Chain   | Rule                                                              |
|---------|-------------------------------------------------------------------|
| input   | accept established / related / untracked                         |
| input   | drop invalid                                                      |
| input   | accept ICMP (ping)                                                |
| input   | accept everything from the LAN                                    |
| input   | record internet hosts probing SSH/WinBox/web/telnet/FTP/API in the `wan-mgmt-attempts` list (kept 1 day) |
| input   | drop everything else (silent, no logging)                        |
| forward | FastTrack established / related                                   |
| forward | accept established / related / untracked                         |
| forward | drop invalid                                                      |
| forward | drop new connections from the WAN that are not port forwards     |

LAN to internet is allowed by default (no final forward drop needed).

**NAT (12 rules)**
- masquerade out of the WAN, plus a hairpin masquerade for LAN to LAN
- port forwards from the WAN list (works with a dynamic IP): emby/jellyfin tcp 8096-8097 and qBittorrent tcp+udp 58946 to `192.168.100.200`; PS5 udp 8572, 9302, 9295-9308, 987 to `192.168.100.148`
- the same emby and qBittorrent forwards for LAN clients using the public / DDNS name

## Install

1. Back up: `/system backup save name=pre-fw` and `/export hide-sensitive file=pre-fw`.
2. Put `firewall.rsc` on the router (Winbox **Files**, or `/tool fetch`).
3. Enter **Safe Mode** (`Ctrl+X`) from a LAN port.
4. `/import file-name=firewall.rsc verbose=yes`
5. `/import file-name=logging.rsc`
6. `/import file-name=verify.rsc`, expect `RESULT: ALL OK`.
7. Leave Safe Mode with `Ctrl+X` to keep the changes.

`firewall.rsc` deletes all existing filter and NAT rules first (start from scratch).
Change the IPs and ports at the top of each section for your network.

## RouterOS notes (learned the hard way)

- `/import` runs each top-level line as its own statement: no `:local` variables, no helper functions. Use `:global`.
- Do not put `$` inside quoted regexes.
- `hw-offload` is not accepted on the FastTrack rule on this version.

## Watching for login attempts and brute force

```
/log print where buffer=auth-log                    # all logins
/log print where buffer=auth-log and message~"failure"   # failed logins only
/ip firewall address-list print where list=wan-mgmt-attempts   # internet hosts probing management ports
```

The internet cannot log in to the router (the input chain drops it); the list shows who tried.
A failed login from a LAN address means a device or person inside the network.

## Secrets

Never commit `.backup` files or raw exports. Export with `/export hide-sensitive`. See `.gitignore`.

## License

See [LICENSE](LICENSE).
