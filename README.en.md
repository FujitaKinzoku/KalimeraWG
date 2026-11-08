<p align="center">
  <a href="README.md">RU · Русский</a> ·
  <a href="README.en.md"><b>EN · English</b></a>
</p>

<p align="center">
  <img src="assets/kinzoku.jpg" alt="KalimeraWG by Kinzoku" width="680">
</p>

<h1 align="center">KalimeraWG</h1>

<p align="center"><em><b>A managed VPN cascade: client → ENTRY → EXIT, with a CDN → FRONT fallback</b><br>
AmneziaWG 3.1 · VLESS+REALITY · CDN/XHTTP · route-aware DNS · optional SOAX/SOCKS5</em></p>

<p align="center">
  <a href="https://github.com/FujitaKinzoku/KalimeraWG/releases/tag/v3.0.2"><img src="https://img.shields.io/badge/release-v3.0.2-7B2CBF" alt="KalimeraWG v3.0.2"></a>
  <img src="https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu 24.04 LTS">
  <img src="https://img.shields.io/badge/AmneziaWG-3.1-7B2CBF" alt="AmneziaWG 3.1">
  <img src="https://img.shields.io/badge/IaC-Ansible-EE0000?logo=ansible&logoColor=white" alt="Ansible">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-2EA44F" alt="MIT License"></a>
</p>

KalimeraWG turns clean Ubuntu 24.04 VPS instances into a reproducible cascade,
creates the first client, and installs operational tools. The primary path is
AmneziaWG to ENTRY plus a dedicated ENTRY–EXIT channel. An optional third role,
FRONT, accepts VLESS/XHTTP directly or through a CDN and exists mainly for
mobile allowlist conditions.

> **v3.0.2 is the current working release** (v3.0 line). The ENTRY–EXIT channel and
> mobile/AWG3+ run on the kernel module with the full AWG 3.1 field set, FRONT
> is installed together with the cascade, and the VLESS uplink is compatible
> with Yandex Cloud CDN. The release was confirmed by a clean ENTRY + EXIT +
> FRONT install on real servers. See [What's new in v3.0.0](#whats-new-in-v300)
> and [CHANGELOG.md](CHANGELOG.md).

## Quick start

| Requirement | Value |
|---|---|
| Servers | two clean Ubuntu 24.04 LTS VPS instances, a third one for FRONT |
| ENTRY | accepts clients and runs the installer; public IPv4 required |
| EXIT | primary egress; public IPv4 required |
| FRONT (optional) | public IPv4 and a domain whose A record points at it; a ready CDN resource for CDN mode |
| Bootstrap access | root and working SSH on every server; `kalimera` key access afterwards |
| Typical time | 20–40 minutes |

Run as `root` on ENTRY:

```bash
curl -fsSL https://raw.githubusercontent.com/FujitaKinzoku/KalimeraWG/v3.0.2/install.sh | bash
```

The command installs the immutable `v3.0.2` tag rather than the moving `main`
branch. Confirm the local version with `./deploy --version`. Enter the EXIT and
FRONT addresses as IPv4 literals, not DNS names.

For FRONT behind a CDN, prepare the origin domain (A record to FRONT) and the
CDN resource beforehand: HTTPS origin on that domain, Host header and SNI set to
the origin domain, caching off. After installation, get the first VLESS profile
on FRONT with `vless-user export initial`. Details:
[docs/front-relay.md](docs/front-relay.md).

## Mobile allowlist conditions

> A new client session is established while mobile allowlist restrictions are
> active through **Russian cloud CDN → FRONT → ENTRY**, and the RU/EXIT routing
> policy remains intact after ingress. This applies to the tested networks and
> CDNs and is not a universal carrier availability guarantee.

<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="assets/whitelist-cascade-en-mobile.svg">
    <img src="assets/whitelist-cascade-en.svg" alt="Three KalimeraWG ingress paths including the field-validated CDN and FRONT fallback" width="760">
  </picture>
</p>

The ingress paths are alternatives rather than stacked transports. AWG remains
the fast primary path. VLESS/XHTTP always terminates on FRONT: the client can
use the FRONT origin directly or a reachable CDN edge.

| Client path | Transport | Purpose | Validation status |
|---|---|---|---|
| client → ENTRY | AmneziaWG 3+, UDP/443 or mobile UDP/8443 | lowest-overhead primary path | previously validated |
| client → FRONT | TLS + VLESS/XHTTP, TCP/443 | direct VLESS without CDN; no public VLESS listener on ENTRY | implemented |
| client → CDN → FRONT | TLS + VLESS/XHTTP, TCP/443 | ingress through a reachable CDN edge | field-validated |
| FRONT → ENTRY | VLESS+REALITY | protected service hop available only from FRONT | field-validated |
| ENTRY → EXIT / RU | AWG 3+ or SOCKS5/fail-open | unchanged destination policy | retained |

The XHTTP uplink uses bodyless GET requests with the payload in headers: since
30 September 2026 Yandex Cloud CDN answers `413` to any GET with a body. Upload
through the CDN is therefore limited to about 2.2 Mbit/s; download is not.

Carrier, region, DNS, CDN edge, and filtering policy can change independently.
See [docs/front-relay.md](docs/front-relay.md) for the detailed architecture,
failure matrix, deployment notes, and current limitations.

## What's new in v3.0.0

| Area | v2.1.0 | v3.0.0 |
|---|---|---|
| ENTRY–EXIT channel | userspace `amneziawg-go`, AWG 3.0 | kernel module with the full AWG 3.1 field set; 0.85% loss on the channel instead of 6–8% |
| mobile | separate profile | mobile/AWG3+ on the kernel module, full AWG 3.1 profile on UDP/8443 |
| FRONT | none | third role: VLESS/XHTTP directly or through a CDN, REALITY service hop to ENTRY, installed with the cascade |
| CDN | - | bodyless uplink compatible with Yandex Cloud CDN; ML-KEM-768 VLESS Encryption |
| Obfuscation | fixed profile structure | AWG profile structure randomized per installation |
| Reliability | - | the FRONT backend comes back by itself after reboot; VLESS egresses through EXIT, not ENTRY |
| Checks | - | `awg-health` verifies the full AWG 3.1 profile and that the uplink passes the CDN |

After upgrading an existing cascade, VLESS client profiles must be exported
again (`vless-user export NAME`) and mobile profiles recreated. Full list in
[CHANGELOG.md](CHANGELOG.md), section `[3.0.0]`.

**v3.0.1:** size randomization (`ContentPaddingAddition`, `RandomTrailers`) is
off on mobile/AWG3+: with it the profile lost about 5% of packets. On cascades
installed earlier, change the values in `group_vars/entry.yml` by hand and then
reissue mobile configs, see [docs/awg3.md](docs/awg3.md).

**v3.0.2:** the installer disables `fwupd-refresh.timer`: on VPS it timed out
daily and left a failed unit for `server-audit`.

### What came in v2.0.0

`v2.0.0` is a security-hardening package on top of `v1.0.0`: ports, MTU, DNS
policy, and cascade routing are unchanged. Highlights:

| Area | v1.0.0 | v2.0.0 |
|---|---|---|
| Administration | everyday work as `root` over SSH keys | dedicated `kalimera` account; `root` SSH is restricted to the automation source address |
| Passwords | a single `root` password | 4 independent 30-character `kalimera`/`root` passwords per ENTRY and EXIT, shown once; only SHA-512 hashes remain in Vault |
| On-disk secrets | plain AWG/AWG3/sing-box/Telegram config files | Shamir `2-of-5` threshold protection + AES-256-GCM; plaintext only in `/run`, configs delivered via systemd credentials |
| Cascade boot | services start immediately | fail-closed startup: waits for a share quorum, verifies pinned SSH host keys, refuses to start on a missing/modified package |
| SSH | key-only access, Fail2Ban | additionally: hidden banner, no user startup files, automation key restricted to its source address, separate recovery admin key |
| Log retention | standard journald and Fail2Ban | no-logs policy: journald/Fail2Ban/login accounting stay in RAM; UFW/sing-box/DNS query logs, shell history, and coredumps are disabled |
| Auditing | `server-audit` | added `ssh-key-audit` (foreign root keys) and an expanded `server-audit` (public listeners, no-logs policy compliance) |
| Cascade reliability | - | fixed routing/AWG3 boot races, added EXIT-route self-healing, removed false health-check failures after reboot |
| Kernel/DKMS | checks `/vmlinuz` | guard now recognizes every installed kernel, including signed/unsigned kernel packages |

See the full changelog in [CHANGELOG.md](CHANGELOG.md) (the `[2.0.0]` section) and the
threat model for the new mechanisms in
[docs/RUNTIME-SECRETS.md](docs/RUNTIME-SECRETS.md) and
[docs/security-boundary.md](docs/security-boundary.md).

## Architecture

<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="assets/cascade-en-mobile.svg">
    <img src="assets/cascade-en.svg" alt="KalimeraWG routing diagram" width="760">
  </picture>
</p>

| Segment | Purpose | Default state |
|---|---|---|
| `awg0`, UDP/443 | modern clients | enabled |
| `awg-mobile`, UDP/8443 | dedicated mobile/AWG3+ with the full AWG 3.1 profile | enabled on first mobile peer |
| `awg-old` | KeeneticOS 4.3.x compatibility | enabled on first old peer |
| `awg3`, EXIT UDP/443 | independent ENTRY–EXIT transit | enabled |

Every interface, transit included, is brought up by the AmneziaWG kernel
module. A fallback userspace engine based on `amneziawg-go` is kept for the
transit channel only; it is selected with `scripts/toggle-transit-engine.py`
and is not used by default - see [docs/awg3.md](docs/awg3.md).

The public AWG3 port on EXIT is allowed only from the known ENTRY IPv4. Client
and transit segments use separate interfaces, keys, and parameters.

## Choose a profile

| Requirement | Recommended option |
|---|---|
| General-purpose cascade | `balanced` |
| Highest supported obfuscation | `masking` + AWG 3+ transit |
| AmneziaWG 5.0.1.5 or newer | `mobile/AWG3+` on UDP/8443 |
| KeeneticOS 4.3.x | `old` on the compatibility interface |
| Highest client performance | `performance` |
| Russian residential/mobile egress | SOAX or another SOCKS5 provider |

### Validated compatibility

| Path | `v3.0.0` validation |
|---|---|
| Ubuntu 24.04 LTS | clean ENTRY + EXIT + FRONT install on real VPS; reboot and strict audit on live cascades |
| ENTRY–EXIT | fresh AWG 3.1 handshake on the kernel module, coordinated MTU, and post-reboot recovery |
| mobile/AWG3+ | full AWG 3.1 profile, real client connections |
| KeeneticOS | `balanced` and `old` profiles for current and compatibility firmware branches |
| RU SOCKS5 | TCP/UDP probing, watchdog, fail-open through ENTRY, and automatic recovery |
| Mobile allowlist | new session via Russian cloud CDN → FRONT → ENTRY while retaining RU/EXIT routing |
| Yandex Cloud CDN | bodyless uplink verified on real Xray v26.7.28 and with live probes through the CDN |

This matrix records scenarios that were actually exercised. It cannot guarantee
identical behavior across every carrier, hosting provider, and client version.

```bash
vpn-user phone balanced
vpn-user iphone mobile
vpn-user tablet mobile/awg3+
vpn-user list
vpn-user delete phone
```

## Routing and DNS

| Policy | Route | DNS transport |
|---|---|---|
| default and `se-domain` | ENTRY → AWG3 → EXIT | Unbound → DoT |
| `entry-domain` | ENTRY WAN | managed local resolver |
| RU networks and `ru-domain` | ENTRY WAN or SOCKS5/TUN | DoH through the RU proxy when available |
| SOCKS5 outage | automatic fail-open through ENTRY | default DoT remains available |

Client DNS is redirected to the local ENTRY resolver. Runtime policy uses
`ipset`, `iptables`, packet marks, and dedicated routing tables.

## Reliability

| Mechanism | Purpose |
|---|---|
| bidirectional PMTU | coordinated MTU without avoidable fragmentation |
| TCP MSS clamp | reliable TCP inside the cascade |
| kernel/DKMS guard | prevents reboot into a kernel without AmneziaWG |
| transactional component updates | validated ENTRY/EXIT update with rollback |
| bounded DNS/APT/SSH/AWG3 retries | tolerates transient provider failures |
| SOCKS5 watchdog | stateful fail-open and recovery |
| health/audit gates | detect service, firewall, DNS, and routing drift |
| Telegram | alerts on reboot, failover, and recovery |

## Security

| Boundary | Implementation |
|---|---|
| Secrets | Ansible Vault, `no_log`, mode `0600`, no client configs in Git/CI |
| SSH | dedicated `kalimera` account; key access is verified before old ports close; Fail2Ban follows |
| Privileges | project commands use a root-owned allowlist; unrestricted sudo still requires the user password |
| Passwords | four independent 30-character values are shown once; only hashes remain in Vault |
| Firewall | deny-by-default UFW; AWG3 limited to known ENTRY/EXIT IPv4 peers |
| Updates | candidate validation, exact applied-version lock, automatic rollback |
| Kernel | headers, DKMS and `modinfo` verified for the running and newest installed kernels |
| DNS | local Unbound, validated DoT/DoH, provider-DNS failure resilience; `/etc/resolv.conf` and `nsswitch.conf` are forced onto `systemd-resolved` regardless of hosting provider (v2.0.1); optionally, the default branch resolves via its own DNSSEC-validating recursion on EXIT inside the AWG tunnel instead of external DoT, so no separate TLS ClientHello leaves ENTRY (v2.1.0) |
| No-logs | journal and login accounting stay in RAM; UFW/sing-box/DNS query logs, shell history, and coredumps are disabled |
| On-disk secrets | Shamir `2-of-5` + AES-256-GCM; plaintext configuration only in `/run`; services receive AWG/AWG3/sing-box/Telegram config via systemd credentials |
| AWG3 failures | bounded retries and sanitized diagnostics without key material |
| VPS networking | compatible with both ifupdown and systemd-networkd without replacing the hosting provider's network manager |
| Repository | Gitleaks plus YAML, Ansible, Shell, and Python checks |

See [SECURITY.md](SECURITY.md) and
[docs/security-boundary.md](docs/security-boundary.md) for the threat model.

## Operations

| Area | Commands |
|---|---|
| State | `kalimera-status`, `awg-health --strict`, `server-audit` |
| Clients | `vpn-user`, `awg-mobile`, `awg-old` |
| DNS | `dns-status`, `dot-switch`, `doh-switch` |
| Routing | `ru-domain`, `se-domain`, `entry-domain`, `ru-direct-ports` |
| Proxy | `ru-proxy`, `ru-proxy-set` |
| Security | `fail2ban-client status sshd`, `f2b-reset`, `ssh-key-audit status`, `telegram-test` |
| Maintenance | `maintenance`, `update-all`, `kalimera-deploy --resume` |

Normal post-installation administration uses the `kalimera` account. Project
commands do not require typing `sudo`; arbitrary system changes still require
the one-time displayed `kalimera` password, so no unrestricted passwordless
root shell is created.

Validation on both nodes:

```bash
awg-health --strict
server-audit
systemctl --failed --no-pager
```

## Documentation

| Document | Content |
|---|---|
| [docs/interactive-deploy.md](docs/interactive-deploy.md) | installation flow |
| [docs/awg3.md](docs/awg3.md) | AWG 3+ transit |
| [docs/security-boundary.md](docs/security-boundary.md) | secrets, UFW and trust boundaries |
| [docs/acceptance.md](docs/acceptance.md) | acceptance checks |
| [docs/front-relay.md](docs/front-relay.md) | field-validated CDN/FRONT allowlist path and its limitations (Russian) |
| [docs/upstream.md](docs/upstream.md) | pinned upstream components |
| [CHANGELOG.md](CHANGELOG.md) | release history |

## Scope

KalimeraWG does not guarantee anonymity, IP reputation, third-party proxy
availability, or access through every network. It does not make cleartext
traffic beyond the VPN exit end-to-end encrypted. Users remain responsible for
lawful use and provider terms.

KalimeraWG is not an official Amnezia VPN project. Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<p align="center"><b>KalimeraWG v3.0.2 · a managed cascade with a CDN fallback</b></p>
