# mitm-delay — delay-only PTP MitM forwarder (any DPDK NIC)

A transparent L2 bump-in-the-wire for PTP **time delay attacks** that runs on
**stock DPDK on any poll-mode driver** (Intel X710/i40e, Mellanox mlx5,
Broadcom bnxt, …). No i210, no HWTS, no PPS wire, **no driver patch**.

It forwards every frame between its two ports unmodified, and holds back PTP
*event* messages in one direction to inject path asymmetry. The victim slave's
clock offset shifts by **delay / 2**. All other traffic (e.g. O-RAN eCPRI
C/U/M-plane) is forwarded immediately — the delay uses a release queue, not a
busy-wait, so it never stalls the fronthaul user plane.

This is the lightweight sibling of [`../mitm-attacker`](../mitm-attacker), which
is a full i210 transparent clock (HWTS + PPS-synced dual PHCs) that also hides
its own residence time. Use that one only if you must evade a TC-aware or
PTPsec-style detector.

## Topology

```
[GM / DU / switch] ── port0 ─┤ mitm-delay ├─ port1 ── [PTP slave: Benetel RU]
```

## Build

Needs DPDK ≥ 21.11 dev files. Either the distro package:

```bash
sudo apt install -y build-essential dpdk-dev pkg-config libnuma-dev
```

or a self-built DPDK on `PKG_CONFIG_PATH`. Then:

```bash
make
```

→ `build/mitm-delay`.

## Run

Bind the two tap NICs to DPDK and set up hugepages (safe helper — refuses to
touch your SSH NIC):

```bash
./setup.sh 0000:45:00.0 0000:45:00.1
```

Start with no attack, then launch:

```bash
echo 0 > delay.txt && sudo ./build/mitm-delay -l 0 -n 4
```

## Attack control (live, no restart)

Write microseconds to `delay.txt`. The **sign selects the direction**:

| `delay.txt` | Direction delayed | Victim slave offset |
|-------------|-------------------|---------------------|
| `+D`        | Delay_Req (slave→master) | ≈ +D/2 |
| `-D`        | Sync (master→slave)      | ≈ −D/2 |
| `0`         | none (pass-through)      | 0 |

```bash
echo 200 > delay.txt     # delay Delay_Req path by 200 us
echo -50 > delay.txt     # delay Sync path by 50 us
echo 0   > delay.txt     # stop the attack, stay inline
```

## Transports handled

- L2 PTP, EtherType `0x88F7`, including one/two stacked **VLAN** tags
  (802.1Q / QinQ) — the common O-RAN G.8275.1 case.
- UDP/IPv4 PTP (dst port 319/320).

## Caveats

- **SyncE:** a store-and-forward node terminates the physical SyncE chain. If
  the RU runs SyncE-assisted (LLS-C), it may raise a sync alarm or fail to lock
  frequency independent of your PTP delay. Confirm PTP-only vs SyncE-assisted.
- **Throughput:** single RX/TX queue on one core. Every 2 s the app prints a
  per-port `[stats]` line; a nonzero `miss` (or the `<-- DROPPING` flag) means
  the core can't keep up with ingress. eCPRI U-plane frames are large (low pps),
  so one core is normally plenty. If you do see sustained `miss`, the right fix
  here is **one lcore per direction** (2 cores, no extra queues), not RSS — RSS
  can't spread a 2-endpoint, non-IP eCPRI link. Ask and I'll add it.
- **Not stealthy:** the node's own forwarding latency shows up as (symmetric)
  path delay. It does not fake a correctionField. That does not affect the
  offset attack, but a path-asymmetry detector like PTPsec is designed to catch
  exactly this.
