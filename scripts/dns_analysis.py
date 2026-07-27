#!/usr/bin/env python3
"""
Part 4 - DNS analysis.

Identifies DNS query domains/subdomains, classifies them (and, where no
DNS/SNI hostname was observed, the raw destination IP via a best-effort
RDAP/org lookup) into cloud-provider / CDN categories, and produces a
DNS query volume timeline.

Usage: python3 dns_analysis.py <device> <full.csv> <figures_dir> <tables_dir>
"""
import sys
import time
import subprocess
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CLOUD_KEYWORDS = [
    ("Amazon / AWS / Alexa", ["amazonaws.com", "amazon.com", "amazonalexa.com", "a2z.com"]),
    ("Google", ["google.com", "googleapis.com", "gstatic.com", "1e100.net", "googleusercontent.com"]),
    ("Microsoft / Azure", ["azure.com", "windows.net", "microsoft.com", "msftncsi.com"]),
    ("Cloudflare", ["cloudflare.com", "cloudflare.net"]),
    ("Fastly", ["fastly.net", "fastlylb.net"]),
    ("Akamai", ["akamai.net", "akamaiedge.net", "akamaitechnologies.com"]),
    ("Philips / Hue vendor cloud", ["meethue.com", "philips.com"]),
    ("Somfy vendor cloud", ["opendoors.net", "somfy.com"]),
    ("Apple", ["apple.com", "icloud.com"]),
    ("NTP pool", ["pool.ntp.org", "ntp.org"]),
    ("mDNS / local service discovery", ["local"]),
]


def classify_domain(name):
    if not isinstance(name, str):
        return "Unclassified"
    lname = name.lower()
    for label, keywords in CLOUD_KEYWORDS:
        if any(kw in lname for kw in keywords):
            return label
    return "Unclassified / other"


_org_cache = {}


def lookup_org(ip):
    if ip in _org_cache:
        return _org_cache[ip]
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", "3", f"https://ipinfo.io/{ip}/org"],
            capture_output=True, text=True, timeout=5,
        )
        org = out.stdout.strip() or "Unknown (lookup failed)"
    except Exception:
        org = "Unknown (lookup failed)"
    _org_cache[ip] = org
    time.sleep(0.15)
    return org


def main():
    device, csv_path, fig_dir, tab_dir = sys.argv[1:5]
    df = pd.read_csv(csv_path, dtype=str)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")

    dns = df.dropna(subset=["dns.qry.name"]).copy()
    dns_queries = dns[dns["dns.flags.response"] != "1"]  # queries, not responses
    qcounts = dns_queries["dns.qry.name"].value_counts()
    qcounts.to_csv(f"{tab_dir}/{device}_dns_queries.csv", header=["query_count"])

    dns["classification"] = dns["dns.qry.name"].map(classify_domain)
    class_counts = dns.groupby("classification").size().sort_values(ascending=False)
    class_counts.to_csv(f"{tab_dir}/{device}_dns_cloud_classification.csv", header=["dns_record_count"])

    fig, ax = plt.subplots(figsize=(7, 4))
    class_counts.plot(kind="bar", ax=ax, color="#4C72B0")
    ax.set_title(f"{device.capitalize()}: DNS Records by Cloud/CDN Classification")
    ax.set_xlabel("Classification")
    ax.set_ylabel("DNS record count")
    plt.xticks(rotation=30, ha="right")
    fig.savefig(f"{fig_dir}/{device}_dns_cloud_classification.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/{device}_dns_cloud_classification.svg", bbox_inches="tight")
    plt.close(fig)

    # DNS query volume timeline
    t0 = dns_queries["frame.time_epoch"].min()
    dns_queries["bin"] = ((dns_queries["frame.time_epoch"] - t0) // 60) * 60
    timeline = dns_queries.groupby("bin").size()
    timeline.to_csv(f"{tab_dir}/{device}_dns_query_timeline.csv", header=["query_count"])

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(timeline.index, timeline.values, color="#C44E52", marker="o", markersize=3)
    ax.set_title(f"{device.capitalize()}: DNS Query Volume Over Time (60s bins)")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel("DNS queries")
    fig.savefig(f"{fig_dir}/{device}_dns_query_timeline.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/{device}_dns_query_timeline.svg", bbox_inches="tight")
    plt.close(fig)

    # Enrich external IPs with no DNS/SNI hostname observed, via org lookup (best-effort, capped)
    all_hosts = set(dns["dns.qry.name"].dropna())
    external_ips = df.dropna(subset=["ip.dst"])["ip.dst"].value_counts().head(20).index.tolist()
    enrichment = []
    for ip in external_ips[:15]:
        org = lookup_org(ip)
        enrichment.append({"ip": ip, "org_lookup": org})
    pd.DataFrame(enrichment).to_csv(f"{tab_dir}/{device}_ip_org_enrichment.csv", index=False)

    print(f"[{device}] {len(qcounts)} distinct DNS query names, "
          f"{len(class_counts)} classification buckets")
    print(class_counts.to_string())


if __name__ == "__main__":
    main()
