<p align="center">
  <a href="README.md">RU · Русский</a> ·
  <a href="README.en.md"><b>EN · English</b></a>
</p>

<p align="center">
  <img src="assets/kinzoku.jpg" alt="KalimeraWG by Kinzoku" width="680">
</p>

<h1 align="center">KalimeraWG</h1>

<p align="center"><em><b>A managed AWG cascade: client → ENTRY → EXIT</b><br>
AmneziaWG 3+ · automatic PMTU/MTU · route-aware DNS · optional SOAX/SOCKS5</em></p>

<p align="center">
  <a href="https://github.com/FujitaKinzoku/KalimeraWG/releases/tag/v2.1.0"><img src="https://img.shields.io/badge/release-v2.1.0-7B2CBF" alt="KalimeraWG v2.1.0"></a>
  <img src="https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu 24.04 LTS">
  <img src="https://img.shields.io/badge/AmneziaWG-3+-7B2CBF" alt="AmneziaWG 3+">
  <img src="https://img.shields.io/badge/IaC-Ansible-EE0000?logo=ansible&logoColor=white" alt="Ansible">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-2EA44F" alt="MIT License"></a>
</p>

KalimeraWG turns two clean Ubuntu 24.04 VPS instances into a reproducible
ENTRY/EXIT cascade, creates the first client, and installs operational tools.
Release `v2.1.0` has been verified through repeated clean VPS deployments.

> **v2.0.0 is a major security-hardening release.** The access model changed
> (a dedicated `kalimera` administrator instead of everyday root), on-disk
> secrets now get threshold protection, SSH and log-retention policy were
> tightened, and cascade boot races were fixed. See
> [What's new in v2.0.0](#whats-new-in-v200) and [CHANGELOG.md](CHANGELOG.md)
> for details.

## Quick start

| Requirement | Value |
|---|---|
| Servers | two clean Ubuntu 24.04 LTS VPS instances |
| ENTRY | accepts clients; public IPv4 required |
| EXIT | primary egress; public IPv4 required |
| Bootstrap access | root and working SSH on both servers; `kalimera` key access afterwards |
| Typical time | 20–40 minutes |

Run as `root` on ENTRY:

```bash
curl -fsSL https://raw.githubusercontent.com/FujitaKinzoku/KalimeraWG/v2.1.0/install.sh | bash
```

The command installs the immutable `v2.1.0` tag rather than the moving `main`
branch. Confirm the local version with `./deploy --version`.

## What's new in v2.0.0

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
| Cascade reliability | — | fixed routing/AWG3 boot races, added EXIT-route self-healing, removed false health-check failures after reboot |
| Kernel/DKMS | checks `/vmlinuz` | guard now recognizes every installed kernel, including signed/unsigned kernel packages |

See the full changelog in [CHANGELOG.md](CHANGELOG.md) (the `[2.0.0]` section) and the
threat model for the new mechanisms in
[docs/RUNTIME-SECRETS.md](docs/RUNTIME-SECRETS.md) and
[docs/security-boundary.md](docs/security-boundary.md).

## Architecture

<p align="center">
  <img src="assets/cascade-en.svg" alt="KalimeraWG routing diagram" width="100%">
</p>

| Segment | Purpose | Default state |
|---|---|---|
| `awg0`, UDP/443 | modern clients | enabled |
| `awg-mobile`, UDP/8443 | iOS/mobile QUIC-like profile | enabled on first mobile peer |
| `awg-old` | KeeneticOS 4.3.x compatibility | enabled on first old peer |
| `awg3`, EXIT UDP/443 | independent userspace ENTRY–EXIT transit | enabled |

The public AWG3 port on EXIT is allowed only from the known ENTRY IPv4. Client
and transit segments use separate interfaces, keys, and parameters.

## Choose a profile

| Requirement | Recommended option |
|---|---|
| General-purpose cascade | `balanced` |
| Highest supported obfuscation | `masking` + AWG 3+ transit |
| Official AmneziaWG client on iOS | `mobile` on UDP/8443 |
| KeeneticOS 4.3.x | `old` on the compatibility interface |
| Highest client performance | `performance` |
| Russian residential/mobile egress | SOAX or another SOCKS5 provider |

### Validated compatibility

| Path | `v2.1.0` validation |
|---|---|
| Ubuntu 24.04 LTS | repeated clean deployments across different VPS providers, reboot, and strict audit |
| ENTRY–EXIT | fresh AWG 3+ handshake, coordinated MTU, and post-reboot recovery |
| iOS | `mobile` profile on the dedicated UDP/8443 interface in the official AmneziaWG client |
| KeeneticOS | `balanced` and `old` profiles for current and compatibility firmware branches |
| RU SOCKS5 | TCP/UDP probing, watchdog, fail-open through ENTRY, and automatic recovery |

This matrix records scenarios that were actually exercised. It cannot guarantee
identical behavior across every carrier, hosting provider, and client version.

```bash
vpn-user phone balanced
vpn-user iphone mobile
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

## Security in v2.1.0

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
| [docs/upstream.md](docs/upstream.md) | pinned upstream components |
| [CHANGELOG.md](CHANGELOG.md) | release history |

## Scope

KalimeraWG does not guarantee anonymity, IP reputation, third-party proxy
availability, or access through every network. It does not make cleartext
traffic beyond the VPN exit end-to-end encrypted. Users remain responsible for
lawful use and provider terms.

KalimeraWG is not an official Amnezia VPN project. Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<p align="center"><b>KalimeraWG v2.1.0 · two servers, one managed route</b></p>
