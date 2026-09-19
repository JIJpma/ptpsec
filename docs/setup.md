# Setup

This chapter describes the experimental setup used to evaluate the delay-only
MitM forwarder (`mitm-delay`) against a real O-RAN radio unit, and explains
the reasoning behind its hardware topology and software architecture. It
closes by discussing what that architecture buys in terms of timing
precision, what it costs, and what traces the resulting attack leaves for a
detector such as PTPsec to find.

## Hardware Topology

The testbed places a single Ubuntu server as a transparent bump-in-the-wire
between the synchronization source and the device under test:

```
[GM / DU / switch] ── port A ─┤ Ubuntu server (mitm-delay) ├─ port B ── [Benetel RU 550]
```

`port A` faces the network side (switch, and beyond it the grandmaster or DU);
`port B` faces the PTP slave, a Benetel RU 550 radio unit. Both cables are
physically rerouted so that neither end connects directly to the other — all
traffic between them, PTP and O-RAN fronthaul (eCPRI C/U/M-plane) alike,
passes through the server.

This topology has one consequence that shapes the rest of the setup: once the
forwarder is running, both `port A` and `port B` are owned by DPDK and are no
longer visible to the Linux kernel — no IP address, no interface, nothing an
SSH session could use. The server therefore needs a **third**, independent
network path for management (a separate NIC/VLAN, or out-of-band access such
as IPMI), since the two ports carrying the attack traffic are unusable for
anything else while the tool is running. The provided `setup.sh` enforces
this indirectly: it identifies whichever interface currently holds the
default route and refuses to bind it to DPDK, so an operator cannot
accidentally sever the very link they are connected over. This is a safety
net, not a substitute for having a real third interface — if the two
attack-facing ports are the only ones available, the tool cannot be started
without losing remote access to the box.

## Software Setup

### Kernel bypass and poll-mode forwarding

`mitm-delay` is built on the Data Plane Development Kit (DPDK) and follows
the standard kernel-bypass pattern used throughout the DPDK ecosystem:

- The two NICs are detached from their normal kernel driver and rebound to
  `vfio-pci`, which hands their PCI register space (and DMA control) to the
  userspace application instead of the kernel network stack.
- The IOMMU (Intel VT-d / AMD-Vi) constrains what physical memory the NIC's
  DMA engine may touch, so a userspace program can be trusted with direct
  hardware access without being able to DMA into arbitrary RAM. Where the
  platform lacks IOMMU support, `vfio-pci` can fall back to an explicitly
  "unsafe" no-IOMMU mode that drops this guarantee.
- A pool of hugepages (2 MB pages, reserved up front by `setup.sh`) backs the
  packet buffer pool (`rte_mbuf`s). Hugepages reduce TLB pressure at high
  packet rates and, more importantly, are pinned and will not be swapped or
  moved — a requirement for memory that a NIC's DMA engine is actively
  writing into.
- Once bound, the application's core does not wait for interrupts. It runs a
  tight, continuously polling loop (`rte_eth_rx_burst` / `rte_eth_tx_burst`)
  that asks each port directly whether a frame is waiting. This is the
  defining trait of a DPDK Poll-Mode Driver (PMD), and it is what "kernel
  bypass" buys on the timing side: no interrupt dispatch, no NAPI softirq
  scheduling, no coalescing delay between a frame landing in the ring and the
  application seeing it.

Because the application only uses the common `rte_eth_dev` API rather than
any vendor-specific extension, it runs unmodified on any NIC with a DPDK PMD
— Intel i40e/ice, Mellanox mlx5, Broadcom bnxt, and others. No driver
patching is required, which is what allows the same binary to be pointed at
whatever NICs the testbed happens to have wired to the switch and to the RU.

### The forwarding loop and attack control

Every frame received on one port is forwarded to the other unmodified. The
only exception is PTP *event* messages (`Sync`, `Delay_Req`) in the direction
currently under attack, which are diverted into a small release queue and
re-transmitted once a configured delay has elapsed. The delay is read from
`delay.txt` roughly ten times per second, so the attack can be started,
changed, or stopped live without restarting the forwarder — supporting both
the static-delay and incremental-delay attack scenarios evaluated in the
PTPsec paper. Holding a packet never blocks the main loop: the release queue
is drained opportunistically on every iteration, so eCPRI user-plane traffic
continues to be forwarded immediately even while a PTP message is being
held.

## Design Rationale

The two tools in this repository sit at different points on the same
tradeoff. `mitm-attacker` uses a hardware-timestamping Intel i210 NIC with a
patched DPDK driver, giving it a sub-100 ns view of exactly when each frame
crossed the wire — precise enough to compensate its own residence time and
write a convincing `correctionField`, i.e. to act as a genuinely stealthy
Transparent Clock. That precision is bought with a hard hardware dependency:
patched driver, specific NIC, PPS-synced dual clocks.

`mitm-delay` deliberately gives that up in exchange for portability. It
targets realistic O-RAN fronthaul testbeds where the available NICs are
whatever the site already has, not a hand-picked HWTS-capable card, and where
standing up a patched driver for every possible NIC vendor is impractical.
The poll-mode architecture is the compromise that makes this viable: it
removes the single largest source of *avoidable* software jitter (interrupt
handling) without requiring any hardware timestamping support at all, so a
plain software delay is still injected with reasonably tight, consistent
timing — just not with hardware-grade precision, and with no attempt to hide
that the delay happened.

## Timing Precision: Advantages and Limitations

**What the architecture buys:**

- No interrupt-, NAPI-, or coalescing-induced jitter on the datapath, since
  the core never sleeps waiting for an interrupt.
- No extra copy latency: the NIC DMAs frames directly into pre-registered
  mbuf memory, and the application reads/writes that same memory.
- A non-blocking hold/release design, so the deliberate delay never becomes
  a bottleneck for the rest of the traffic on the link — important on a
  fronthaul link carrying real eCPRI U-plane data.
- Live, low-latency attack reconfiguration via `delay.txt`, enabling dynamic
  attack profiles without dropping the link.

**What it does not buy:**

- The hold duration is computed from `rte_get_tsc_cycles()`, a CPU cycle
  counter read in software at the moment the polling loop happens to drain
  the ring — not a value latched by the NIC hardware at the instant a frame
  crossed the wire. Some jitter remains between physical arrival and this
  software timestamp (DMA completion time, loop-iteration granularity).
- The testbed as configured does not isolate the forwarding core from the
  rest of the OS scheduler (no `isolcpus`/`nohz_full`, no IRQ affinity
  steering). Without that, an occasional scheduler preemption can still
  stall the poll loop for tens to hundreds of microseconds.
- Two periodic maintenance tasks run on the same core as the forwarding
  loop: the ~10 Hz re-read of `delay.txt` (a blocking file open/read/close)
  and the 2-second throughput/drop-rate printout. Both can briefly stall
  forwarding in both directions when they run.
- A single RX/TX queue on a single core imposes a throughput ceiling;
  sustained drops (visible as a rising `miss` counter in the periodic
  `[stats]` output) indicate the core cannot keep up with ingress, which is
  itself a potential artifact distinct from the intended PTP delay.

In practice this means the tool can reliably reproduce the class of attack
evaluated in the PTPsec paper — static and incremental delays on the order
of tens to hundreds of microseconds — but the resulting offset trace is
visibly noisier than a hardware-timestamped attack would produce, and its
lower bound on usable delay magnitude is set by this residual software
jitter rather than by any fundamental limit of the approach.

## Traces the Attack Leaves

By construction, `mitm-delay` does not touch the `correctionField` and is not
a PTP-aware Transparent Clock — it is a plain L2/L3 bridge that happens to
hold specific packets. Any delay it introduces on the attacked direction is
therefore completely uncompensated: it shows up directly as a non-zero path
asymmetry (`α ≠ 0` in the PTPsec model) between the two directions of the
synchronization path. This is precisely the signal that PTPsec's cyclic
round-trip-time analysis is designed to extract via a redundant path, and it
is why the tool's own documentation describes it as "not stealthy" — the
absence of correctionField compensation is not an oversight, it is the
direct consequence of choosing driver-agnostic portability over the
hardware-timestamping precision that stealth would require.

The bridge's own baseline forwarding latency — the overhead present on every
packet even with no attack configured — is symmetric by construction, since
both directions run through identical code with no direction-dependent
branching outside the deliberate hold path. Per the PTPsec offset model, a
delay that is equal in both directions cancels out of the offset calculation
entirely; it only inflates the reported mean path delay, not the offset used
to detect asymmetry. This is why the baseline residence time does not need
to be hidden the way `mitm-attacker`'s does — only the deliberately
asymmetric, direction-selective hold produces a detectable signature, and
that asymmetry is the entire mechanism of the attack, not an accidental
side-effect.

Beyond timing, inserting a real store-and-forward device inline leaves
non-cryptographic traces as well. Because the link is no longer a direct
physical connection, any SyncE-assisted timing chain (relevant if the RU
runs a partial-timing-support profile such as ITU-T G.8275.2/LLS-C) is
broken independent of the PTP delay, which can raise a sync alarm on its own
and must be distinguished from the intended attack. The inserted hop may
also be visible through ordinary network operations — MAC learning behavior
on the switch, or LLDP if either neighbor advertises it — as a topology
change, independent of anything PTP-specific.
