# FW_Kong – MikroTik Homelab Firewall

RouterOS v7 firewall configuration for a homelab: default-deny, stateful, and kept in Git as reviewable `.rsc` scripts.

> **Status:** baseline. Adjust interface names and the LAN subnet in
> `config/00-base.rsc` before importing. Always test with Safe Mode.

## Goals

- **Default deny** on `input` and `forward`; explicit allows only.
- **Small and simple**: one WAN, one flat LAN; easy to extend to VLANs later.
- **Fast path first**: FastTrack for established/related, then drops.
- **Reproducible**: whole config lives in Git; no click-ops drift.
- **No secrets in the repo** (see `.gitignore`).

## Network model (flat, no VLANs)

| Item          | Value                                              |
|---------------|----------------------------------------------------|
| WAN           | `ether1`, dynamic IP from ISP (DHCP client)        |
| LAN           | `bridge`: `ether2-8`, `sfp-sfpplus1`, `192.168.100.0/24` |
| Router (LAN)  | `192.168.100.1`, DHCP from the existing server    |
| Admin access  | WinBox/SSH from LAN only                           |

Port forwards (emby/jellyfin, qBittorrent, PS5, WireGuard) match on
the `WAN` interface list, so a changing WAN IP does not matter. See
`config/30-portforward.rsc`; fill in the target hosts before importing.

## Rule policy (order matters)

**input chain (traffic to the router)**
1. accept established, related, untracked
2. drop invalid
3. accept ICMP (rate limited)
4. accept everything from `LAN` (WinBox/SSH further limited by `/ip service`)
5. drop everything else (log WAN drops with a rate limit)

**forward chain (traffic through the router)**
1. FastTrack established/related
2. accept established, related, untracked
3. drop invalid
4. drop new WAN→LAN not DSTNATed
5. bogon source check
6. LAN → WAN accept
7. drop everything else

**NAT**: `masquerade` on `WAN`; hairpin masquerade for LAN; explicit `dst-nat`
only for published services (`30-portforward.rsc`).

Extras worth enabling: bogon/`address-list` blocks on WAN, SSH brute-force
stage lists, disabling unused services (`/ip service`, MAC-server, neighbor
discovery on WAN, UPnP), and IPv6 mirror rules (ICMPv6 must stay allowed).

## Repository layout

```
.
├── README.md
├── .gitignore
├── LICENSE
└── config/
    ├── 00-base.rsc        # adopt factory defconf: interface lists, DNS
    ├── 10-firewall.rsc    # address lists, filter, NAT
    ├── 20-hardening.rsc   # disable unused services
    └── 30-portforward.rsc # dstnat + hairpin (fill in target IPs)
```

## Usage

1. Back up first: `/system backup save name=pre-fw` and
   `/export hide-sensitive file=pre-fw`.
2. Upload `.rsc` files (WinBox Files, `scp`, or SFTP).
3. Enter **Safe Mode** (`Ctrl+X` in terminal) so a lockout auto-reverts.
4. Import in order: `00-base.rsc`, `10-firewall.rsc`, `20-hardening.rsc`, `30-portforward.rsc`
   (`/import file-name=10-firewall.rsc`). Start from the factory default config (`defconf`); the firewall script
   removes the default rules and replaces them.
5. Verify LAN access to the router, then leave Safe Mode to commit.

Verify with:

```
/ip firewall filter print stats
/ip firewall connection print count-only
/log print where topics~"firewall"
```

## Secrets policy

- Export with `/export hide-sensitive` only.
- Never commit `.backup` files, WireGuard/VPN keys, PSKs, certificates or
  `.env` files — they are ignored by `.gitignore`. Rotate anything that leaks.

## Maintenance

- Change via PR; describe intent and rollback.
- Re-export sanitized config after any live change to detect drift:
  `/export hide-sensitive file=live` then `diff` against `config/`.
- Keep RouterOS on the stable channel and review release notes for firewall
  behaviour changes.

## License

See [LICENSE](LICENSE).
