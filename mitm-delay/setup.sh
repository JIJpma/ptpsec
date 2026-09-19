#!/usr/bin/env bash
# PTPsec delay-forwarder - host setup: hugepages + bind the two tap NICs to DPDK.
#
# SAFE BY DESIGN: only binds the two PCI devices you pass in, and refuses to
# touch whichever NIC currently holds the default route (i.e. your SSH path).
#
# Usage:
#   ./setup.sh                      # uses the two X710 ports below
#   ./setup.sh 0000:45:00.0 0000:45:00.1
#
# Undo (rebind to the kernel i40e driver):
#   sudo dpdk-devbind.py --bind=i40e 0000:45:00.0 0000:45:00.1
set -euo pipefail

# --- The two X710 fronthaul-tap ports (edit if different) -------------------
PORT0_PCI="${1:-0000:45:00.0}"
PORT1_PCI="${2:-0000:45:00.1}"

DPDK_DEVBIND="${DPDK_DEVBIND:-dpdk-devbind.py}"
HUGEPAGES="${HUGEPAGES:-1024}"          # 2MB pages -> 2 GB

command -v "$DPDK_DEVBIND" >/dev/null 2>&1 || {
	echo "ERROR: dpdk-devbind.py not found."
	echo "  Set DPDK_DEVBIND=/path/to/dpdk/usertools/dpdk-devbind.py and retry."
	exit 1
}

# --- Safety: never bind the NIC that carries the default route --------------
GW_IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
GW_PCI=""
if [ -n "${GW_IFACE:-}" ] && [ -e "/sys/class/net/$GW_IFACE/device" ]; then
	GW_PCI="$(basename "$(readlink -f "/sys/class/net/$GW_IFACE/device")")"
fi
for p in "$PORT0_PCI" "$PORT1_PCI"; do
	if [ -n "$GW_PCI" ] && [ "$p" = "$GW_PCI" ]; then
		echo "REFUSING: $p carries the default route via $GW_IFACE (your SSH)."
		echo "Aborting so we don't cut your connection."
		exit 1
	fi
done
echo "Default route: ${GW_IFACE:-none} (${GW_PCI:-n/a}) - will NOT be touched."
echo "Binding to DPDK: $PORT0_PCI  $PORT1_PCI"
echo

# --- Hugepages --------------------------------------------------------------
echo "$HUGEPAGES" | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages >/dev/null
echo "Hugepages (2MB): $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"

# --- VFIO -------------------------------------------------------------------
sudo modprobe vfio-pci
# If this box has no IOMMU, uncomment the next line to allow no-IOMMU VFIO:
# echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode >/dev/null

# --- Bind -------------------------------------------------------------------
sudo "$DPDK_DEVBIND" --bind=vfio-pci "$PORT0_PCI" "$PORT1_PCI"
echo
sudo "$DPDK_DEVBIND" --status-dev net | head -n 40
echo
echo "Done. Now:  echo 0 > delay.txt  &&  sudo ./build/mitm-delay -l 0 -n 4"
