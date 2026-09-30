# FW_Kong – MikroTik Homelab Firewall

RouterOS v7 firewall configuration for a homelab: default-deny, VLAN-segmented,
stateful, and kept in Git as reviewable `.rsc` scripts.

> **Status:** baseline / template. Adjust interface names, VLAN IDs and subnets
> to your network before importing. Always test with Safe Mode.

## Goals

- **Default deny** on `input` and `forward`; explicit allows only.
- **Segmentation** between trusted, IoT, servers, guest and management.
- **Fast path first**: FastTrack for established/related, then drops.
- **Reproducible**: whole config lives in Git; no click-ops drift.
- **No secrets in the repo** (see `.gitignore`).

## Example network model

| VLAN | Name    | Subnet          | Access policy                                  |
|-----:|---------|-----------------|------------------------------------------------|
|   10 | MGMT    | 10.10.10.0/24   | Reaches router + all VLANs (admin only)        |
|   20 | LAN     | 10.10.20.0/24   | Internet, servers (selected ports)             |
|   30 | SERVERS | 10.10.30.0/24   | Internet (limited), no initiation to LAN       |
|   40 | IoT     | 10.10.40.0/24   | Internet only, DNS/NTP to router, no lateral   |
|   50 | GUEST   | 10.10.50.0/24   | Internet only, client isolation                |

Interface lists: `WAN`, `LAN` (all internal VLANs), `MGMT`.

## Rule policy (order matters)

**input chain (traffic to the router)**
1. accept established, related, untracked
2. drop invalid
3. accept ICMP (rate limited)
4. accept DNS/NTP from internal VLANs as needed
5. accept WinBox/SSH only from `MGMT`
6. drop everything else (log WAN drops with a rate limit)

**forward chain (traffic through the router)**
1. FastTrack established/related
2. accept established, related, untracked
3. drop invalid
4. drop new WAN→LAN not DSTNATed
5. inter-VLAN allow rules (per table above)
6. LAN → WAN accept
7. drop everything else

**NAT**: `masquerade` on `WAN`; explicit `dst-nat` only for published services.

Extras worth enabling: bogon/`address-list` blocks on WAN, SSH brute-force
stage lists, disabling unused services (`/ip service`, MAC-server, neighbor
discovery on WAN, UPnP), and IPv6 mirror rules (ICMPv6 must stay allowed).

## Repository layout

```
.
├── README.md
├── .gitignore
├── LICENSE
└── config/            # (add) .rsc modules, applied in numeric order
    ├── 00-interfaces.rsc
    ├── 10-address-lists.rsc
    ├── 20-filter.rsc
    ├── 30-nat.rsc
    ├── 40-ipv6.rsc
    └── 90-hardening.rsc
```

## Usage

1. Back up first: `/system backup save name=pre-fw` and
   `/export hide-sensitive file=pre-fw`.
2. Upload `.rsc` files (WinBox Files, `scp`, or SFTP).
3. Enter **Safe Mode** (`Ctrl+X` in terminal) so a lockout auto-reverts.
4. Import in order: `/import file-name=20-filter.rsc`
5. Verify access from MGMT, then leave Safe Mode to commit.

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
