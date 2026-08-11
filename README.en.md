<p align="center">
  <a href="README.md">RU · Русский</a> ·
  <a href="README.en.md"><b>EN · English</b></a>
</p>

<p align="center">
  <img src="assets/kinzoku.jpg" alt="KalimeraWG by Kinzoku" width="680">
</p>

<h1 align="center">KalimeraWG</h1>

<p align="center"><em><b>A next-generation ENTRY + EXIT AWG cascade</b><br>
AmneziaWG 3+ · automatic MTU · route-aware DNS · optional SOAX/SOCKS5</em></p>

<p align="center">
  One interactive installer turns two clean Ubuntu VPS instances into a managed
  cascade and creates the first protected VPN client configuration.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu 24.04 LTS">
  <img src="https://img.shields.io/badge/AmneziaWG-3+-7B2CBF" alt="AmneziaWG 3+">
  <img src="https://img.shields.io/badge/IaC-Ansible-red" alt="Ansible">
  <img src="https://img.shields.io/badge/Architecture-x86__64-green" alt="x86_64">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-2EA44F" alt="MIT License"></a>
</p>

## Contents

- [Quick start](#quick-start)
- [KalimeraWG advantages](#kalimerawg-advantages)
- [Choose your setup](#choose-your-setup)
- [How it works](#how-it-works)
- [DNS and RU proxy](#dns-and-ru-proxy)
- [Client profiles](#client-profiles)
- [AWG 3+ transit](#awg-3-transit)
- [Kali-style terminal](#kali-style-terminal)
- [Security](#security)
- [Operations](#operations)
- [Documentation](#documentation)

## Quick start

You need two clean Ubuntu 24.04 LTS VPS instances with public IPv4 addresses:

- **ENTRY** accepts VPN clients and usually resides in Russia;
- **EXIT** provides the primary foreign egress in the required geography.

Run on ENTRY as root:

```bash
curl -fsSL https://raw.githubusercontent.com/FujitaKinzoku/KalimeraWG/main/install.sh | bash
```

**One command · typically 20–40 minutes · two clean Ubuntu 24.04 servers.**

<details>
<summary><b>Manual Git installation</b></summary>

```bash
apt-get -o DPkg::Lock::Timeout=600 update
apt-get -o DPkg::Lock::Timeout=600 install -y git
cd /root
git clone https://github.com/FujitaKinzoku/KalimeraWG.git
cd KalimeraWG
chmod +x deploy
./deploy
```

While the repository is private, clone it with a fine-grained token limited to
this repository and **Contents: Read-only**. Do not embed the token in the
remote URL.

</details>

The Russian-language installer asks for server addresses, current and managed
SSH ports, login credentials, an administrator public SSH key, RU routing mode,
DNS providers, optional proxy and Telegram settings, and the first client name.
Secrets are read without echo and stored only in encrypted Ansible Vault data.
The installer uses a structured Kali-inspired interface and ends with readable
panels for access addresses, routing, DNS, MTU, protected files and next steps.

```bash
./deploy --resume
./deploy --summary
./deploy --terminal-only  # update only the terminal UI and command reference
```

<a id="kalimerawg-advantages"></a>

## KalimeraWG advantages

The initial KalimeraWG release is based on a snapshot verified through multiple
clean and repeated deployments. It includes a separate AWG 3+ userspace transit,
bidirectional PMTU measurement, coordinated client MTU, on-demand iOS/mobile and
legacy interfaces, safe client listing and revocation, kernel/DKMS update guards,
verified login summaries, strict audits, and state-aware Telegram monitoring.

## Choose your setup

| Requirement | Recommended option |
|---|---|
| Reliable RU + foreign cascade | Standard install with direct ENTRY RU egress |
| Strongest supported obfuscation | `masking` client profile + AWG 3+ transit |
| Official AmneziaWG client on iOS | `mobile` profile on separate `awg-mobile`, direct UDP/8443 |
| KeeneticOS 4.3.x compatibility | `old` profile on the separate `awg-old` interface |
| Russian residential/mobile address | Enable SOAX or another SOCKS5 provider |
| Failure notifications | Enable Telegram monitoring during installation |
| Highest client performance | `performance` profile |

## Telegram monitoring

Each node reports its own reboot and post-boot state. ENTRY and EXIT also
observe the transit handshake, so a surviving node reports a prolonged outage
of its peer. ENTRY reports automatic RU-proxy fail-open and proxy recovery;
an intentional `ru-proxy off` does not raise an alert. Unchanged states are
deduplicated. Run `telegram-test` to verify delivery without breaking services.

## Kali-style terminal

Both servers receive a role-aware two-line Bash prompt, pinned `ble.sh` syntax
highlighting and completion, colored standard tools, and concise Russian exit
status explanations. Existing user startup files are not replaced wholesale;
the managed loader is added to `/etc/bash.bashrc`, whose original copy is kept
under `/root/config-backups/terminal`. Colors disable automatically for
non-interactive output, `TERM=dumb`, and `NO_COLOR`.

Each new SSH session also shows a colored, secret-free runtime summary of the
actual endpoints, routing mode, DoT/DoH configuration, negotiated MTU and
security state. Run `kalimera-status` to display only this verified summary or
`kalimera-help` to display the summary and the grouped command reference.

See the Russian technical note: [docs/terminal.md](docs/terminal.md).

## How it works

```text
VPN client
    │ AmneziaWG awg0
    ▼
ENTRY
    ├── RU destinations ─────────► ENTRY WAN or SOAX/SOCKS5
    └── primary/foreign traffic ─► AmneziaWG 3+ awg3 ─► EXIT ─► Internet
```

Linux policy routing uses `ipset`, `iptables`, packet marks and dedicated
routing tables. Mark `0x1` selects EXIT through table `100`; mark `0x2` selects
the optional RU proxy TUN through table `200`. User domain and direct-port lists
are empty after a clean installation.

Domain policy can be changed immediately on ENTRY:

```bash
ru-domain add example.ru
se-domain add example.com
entry-domain add example.org
```

Selected RU TCP ports can bypass a restricted proxy:

```bash
ru-direct-ports add 22
ru-direct-ports add 993
ru-direct-ports list
```

## DNS and RU proxy

```text
client → dnsmasq → route-aware policy
                    ├─ default → Unbound → DNS-over-TLS
                    └─ RU/proxy → sing-box → DoH through SOCKS5
```

The default resolver is Mullvad DoT. RU split DNS uses Yandex DoH through the
same SOCKS5 path when the proxy is active. Both providers, TLS names, endpoints
and the DoH path are configurable during installation. Runtime changes are
validated, survive `deploy --resume`, and roll back automatically on failure:

```bash
dns-status
dot-switch status
dot-switch custom 1.1.1.1 cloudflare-dns.com
doh-switch status
doh-switch custom 1.1.1.1 cloudflare-dns.com /dns-query
```

SOAX is useful when an RU service needs a residential/mobile Russian address or
rejects the hosting address of ENTRY. A generic SOCKS5 provider is also
supported. If the proxy is disabled or becomes consistently unavailable, RU
traffic fails open to ENTRY WAN. TCP, UDP ASSOCIATE and a real proxied DNS query
are tested independently.

## Client profiles

The first client is generated automatically. Additional clients are created on
ENTRY:

```bash
vpn-user fast-client performance
vpn-user normal-client balanced
vpn-user protected-client masking
vpn-user iphone mobile
vpn-user old-router old
vpn-user list
vpn-user delete old-client
```

`vpn-user list` reports profile, address, source, and last-handshake age without
printing keys. Deletion revokes a locally created peer immediately and stores a
root-only backup. Inventory-managed peers must be removed on the controller and
then reconciled with `deploy --resume`.

An inventory created before the separate mobile interface can be upgraded
without reinstalling either server:

```bash
./deploy --resume --enable-mobile
vpn-user iphone mobile
```

The installer creates the missing private key directly inside encrypted Vault,
selects a non-overlapping subnet, adds the UDP/8443 profile, and leaves the
service disabled until the first mobile peer is created. Repeating
`--enable-mobile` is idempotent and does not rotate the key.

Every new client receives an address with its VPN subnet prefix, for example
`Address = 10.66.0.2/24`, instead of a host-only `/32`. Keenetic can therefore
create the connected `10.66.0.0/24` route through AWG and reach the internal
`10.66.0.1` DNS server without a separate static policy. Client `AllowedIPs`
therefore contains only `0.0.0.0/0, ::/0`; a separate DNS prefix is no longer
needed. The `mobile` and `old` profiles use their own subnet prefix and DNS
automatically. Server-side peer addresses remain restricted to a mandatory
individual `/32` for cryptokey routing.

| Profile | Purpose |
|---|---|
| `performance` | Lowest documented junk overhead and maximum speed |
| `balanced` | Balanced performance and obfuscation |
| `masking` | Strongest configured masking within documented limits |
| `mobile` | iOS-confirmed QUIC Initial-shaped I1 on a separate direct UDP/8443 endpoint |
| `old` | Basic ASC for KeeneticOS 4.3.x on a separate interface |

Modern profiles contain the full configured field set supported by the selected
implementation and compatible clients: `Jc/Jmin/Jmax`, `S1–S4`, dynamic
`H1–H4` ranges, `I1–I5` and cascade-aligned MTU. Server-side S/H/I values are
copied exactly to every peer on the same interface; only documented client junk
parameters and key material differ.

The `mobile` profile uses a separate key, subnet and `awg-mobile` interface.
Its iOS-confirmed QUIC Initial-shaped `I1` is used without `I2–I5`, which current
mobile clients may reject. The interface listens directly on WAN UDP/8443 only
while active. External UDP/53 is not redirected and remains reserved for DNS
inside the VPN; upgrades automatically remove legacy UDP/53-to-39746 rules.

The `old` interface stays disabled until the first old client is created and can
be managed independently:

```bash
awg-old status
awg-old on
awg-old off

awg-mobile status
awg-mobile on
awg-mobile off
```

## AWG 3+ transit

ENTRY and EXIT use a dedicated userspace `awg3` interface, UDP port, subnet,
private keys and PSK. The transit port is accepted by UFW only from the known
public address of the other server.

<details>
<summary><b>Advanced AWG 3+ and MTU details</b></summary>

Pinned upstream `amneziawg-go` and `amneziawg-tools` revisions are built with a
pinned Go toolchain and cached by revision and architecture. Transit uses the
available `HeaderProtectionKey`, `ContentPaddingAddition`, content/timing
ranges, `I1–I5` and randomized keepalive parameters.

Both servers independently probe IPv4 PMTU without fragmentation. Temporary
ICMP access is restricted to the other server and removed in an unconditional
cleanup block. The lower safe result becomes the transit MTU. Modern client MTU
is capped at `min(awg3 MTU, 1380)`; legacy MTU is capped at `1280`. TCP MSS is
clamped to the effective PMTU.

</details>

## Security

- Fail2Ban is enabled only after key access through the managed SSH port is
  verified.
- SSH becomes key-only; passwords, keyboard-interactive login and forwarding
  features are disabled.
- UFW exposes only active SSH and AWG ports. The AWG 3+ port is additionally
  restricted by peer public IP.
- Client and transit AWG segments use independent private keys and PSKs.
- DNS transport uses DoT/DoH with TLS name validation.
- Secrets stay in Ansible Vault; client files are root-only and excluded from
  Git.
- Automated security updates, health checks, audit and maintenance timers are
  installed.
- Before an update completes, KalimeraWG installs headers and verifies the
  AmneziaWG DKMS module for both the running kernel and the next boot kernel,
  preventing a planned reboot from leaving the cascade without its module.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Operations

ENTRY commands:

```text
awg-health         vpn-user          awg-old          awg-mobile
ru-domain          se-domain         entry-domain
ru-proxy           ru-proxy-set      ru-direct-ports
dns-status         dot-switch        doh-switch
kalimera-help      kalimera-status   telegram-test
maintenance
update-all         server-audit      f2b-reset
```

EXIT commands:

```text
awg-health         maintenance       update-all         kalimera-status
server-audit       f2b-reset
```

After installation, run on both servers:

```bash
awg-health --strict
server-audit
systemctl --failed --no-pager
```

## Documentation

- [Interactive deployment](docs/interactive-deploy.md)
- [AWG 3+ implementation](docs/awg3.md)
- [Security boundaries](docs/security-boundary.md)
- [Clean-VPS acceptance](docs/acceptance.md)
- [Upstream sources and licensing](docs/upstream.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Responsible use

KalimeraWG is intended only for lawful administration of systems owned by the
operator or systems the operator is explicitly authorized to manage. It is not
intended for unauthorized access, interference with third-party systems,
malware distribution, phishing, spam, denial-of-service activity, or using
GitHub as operational proxy infrastructure. Operators are responsible for
applicable law, provider terms, and third-party service conditions.

KalimeraWG is distributed under the [MIT License](LICENSE). Third-party components
retain their own licenses and notices described in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<p align="center"><b>Controlled routes. Protected DNS. Reproducible infrastructure.</b></p>
