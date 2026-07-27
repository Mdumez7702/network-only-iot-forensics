#!/usr/bin/env python3
"""
Part 2 - Device identification.

For a given full-fields CSV (extract_full.sh output), identifies MAC
addresses, resolved manufacturers, IP addresses, protocol usage, and
classifies traffic as unicast / broadcast / multicast. Produces:
  Tables/<device>_device_inventory.csv
  Tables/<device>_broadcast_multicast.csv

Usage: python3 device_id.py <device> <full.csv> <tables_dir>
"""
import sys
import pandas as pd

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_multicast_mac(mac):
    if not isinstance(mac, str) or len(mac) < 2:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x01) and mac.lower() != BROADCAST_MAC


def classify(mac):
    if not isinstance(mac, str):
        return "unknown"
    if mac.lower() == BROADCAST_MAC:
        return "broadcast"
    if is_multicast_mac(mac):
        return "multicast"
    return "unicast"


def main():
    device, csv_path, tables_dir = sys.argv[1:4]
    df = pd.read_csv(csv_path, dtype=str)

    # MAC / manufacturer inventory (src and dst merged)
    src = df[["eth.src", "eth.src.oui_resolved", "ip.src"]].rename(
        columns={"eth.src": "mac", "eth.src.oui_resolved": "manufacturer", "ip.src": "ip"}
    )
    dst = df[["eth.dst", "eth.dst.oui_resolved", "ip.dst"]].rename(
        columns={"eth.dst": "mac", "eth.dst.oui_resolved": "manufacturer", "ip.dst": "ip"}
    )
    inventory = pd.concat([src, dst], ignore_index=True).dropna(subset=["mac"])
    inventory["traffic_class"] = inventory["mac"].map(classify)
    inventory["manufacturer"] = inventory["manufacturer"].fillna("Unresolved / no OUI match")

    summary = (
        inventory.groupby(["mac", "manufacturer", "traffic_class"])
        .agg(ip_addresses=("ip", lambda s: ",".join(sorted(set(s.dropna())))),
             packet_involvement=("mac", "count"))
        .reset_index()
        .sort_values("packet_involvement", ascending=False)
    )
    summary.to_csv(f"{tables_dir}/{device}_device_inventory.csv", index=False)

    bmc = inventory[inventory["traffic_class"].isin(["broadcast", "multicast"])]
    bmc_summary = (
        bmc.groupby(["ip", "traffic_class"]).size().reset_index(name="packet_count")
        .sort_values("packet_count", ascending=False)
    )
    bmc_summary.to_csv(f"{tables_dir}/{device}_broadcast_multicast.csv", index=False)

    print(f"[{device}] Device inventory: {len(summary)} distinct MACs")
    print(summary.to_string(index=False))
    print(f"[{device}] Broadcast/multicast destinations: {len(bmc_summary)}")


if __name__ == "__main__":
    main()
