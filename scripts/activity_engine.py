#!/usr/bin/env python3
"""
Parts 7/8 - Activity reconstruction rule engine + forensic timeline.

Combines outputs from every prior analysis stage (traffic-state
segmentation, session-level periodicity, DNS classification, TLS/JA3,
broadcast/multicast device-discovery traffic) into a single, time-ordered
forensic event timeline. Each event is produced by an explicit,
documented decision rule (see RULES below / Part 17 of the brief) and is
assigned a High/Medium/Low confidence label according to a fixed,
declared scoring policy -- not an ad hoc judgement call per event.

CONFIDENCE POLICY
  HIGH   - the observed pattern is unambiguous by protocol definition
           (e.g. an SSDP/mDNS message IS a discovery message) OR is
           corroborated by >=2 independent signal types (e.g. a traffic
           burst that coincides with a fresh DNS resolution AND a new
           TLS session to the same endpoint).
  MEDIUM - the pattern is consistent with the inferred activity but the
           same network signature could plausibly arise from more than
           one underlying cause (e.g. a large sustained burst could be
           a voice interaction, an audio stream, or a firmware/software
           update -- volume and duration alone cannot disambiguate
           without payload access).
  LOW    - only a single weak/indirect indicator is available, the
           sample size is small, or the inference is speculative absent
           corroborating evidence.

Usage: python3 activity_engine.py <device> <tables_dir> <results_dir> [<full_csv_path>]
"""
import sys
import pandas as pd
import numpy as np

pd.set_option("display.width", 200)

# Hostname-keyword corroboration for burst events: if a DNS/SNI lookup to a
# hostname matching one of these keyword sets occurs shortly before/during a
# burst, that is direct, named-service evidence for the burst's likely cause
# -- much stronger than volume/timing alone.
UPDATE_KEYWORDS = ["update", "upgrade", "firmware", "ota"]
VOICE_KEYWORDS = ["tts", "asr", "speech", "voice", "alexa", "avs"]


def safe_read(path, **kwargs):
    try:
        return pd.read_csv(path, **kwargs)
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def load_named_events(full_csv_path):
    """Return sorted list of (t0_relative_seconds, hostname) for every DNS
    query / TLS SNI hostname observed in the capture."""
    if not full_csv_path:
        return []
    df = safe_read(full_csv_path, dtype=str,
                    usecols=lambda c: c in ("frame.time_epoch", "dns.qry.name",
                                             "tls.handshake.extensions_server_name"))
    if df.empty:
        return []
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    t0 = df["frame.time_epoch"].min()
    df["t0"] = df["frame.time_epoch"] - t0
    events = []
    for col in ("dns.qry.name", "tls.handshake.extensions_server_name"):
        sub = df.dropna(subset=[col])
        events.extend(zip(sub["t0"].tolist(), sub[col].tolist()))
    return sorted(events)


def nearby_hostnames(named_events, start, end, lead=90, trail=5):
    return [h for t, h in named_events if (start - lead) <= t <= (end + trail)]


def merge_runs(segmentation):
    """Run-length encode contiguous bins with the same traffic state into events."""
    segs = []
    if segmentation.empty:
        return segs
    segmentation = segmentation.sort_values("bin")
    cur_state, cur_start, cur_end, cur_packets = None, None, None, 0
    for _, row in segmentation.iterrows():
        if row["state"] != cur_state:
            if cur_state is not None:
                segs.append((cur_state, cur_start, cur_end, cur_packets))
            cur_state, cur_start, cur_packets = row["state"], row["bin"], 0
        cur_end = row["bin"] + 10
        cur_packets += row["packets"]
    if cur_state is not None:
        segs.append((cur_state, cur_start, cur_end, cur_packets))
    return segs


def main():
    device, tab_dir, res_dir = sys.argv[1:4]
    full_csv = sys.argv[4] if len(sys.argv) > 4 else None
    named_events = load_named_events(full_csv)
    events = []

    def add(t, evidence, packets, protocols, reasoning, activity, confidence):
        events.append({
            "time_s": round(float(t), 1), "device": device, "evidence": evidence,
            "observed_packets": packets, "protocols": protocols,
            "reasoning": reasoning, "likely_activity": activity, "confidence": confidence,
        })

    # --- Rule 1: broadcast / multicast -> device discovery ---------------
    bmc = safe_read(f"{tab_dir}/{device}_broadcast_multicast.csv")
    for _, row in bmc.iterrows():
        add(0, f"{row['traffic_class']} traffic to {row['ip']}", int(row["packet_count"]),
            "SSDP/mDNS/ARP (L2 broadcast or multicast)",
            "Broadcast/multicast addressing is, by protocol definition, used for local "
            "service discovery and presence advertisement, not directed application data.",
            f"Device discovery / local service advertisement ({row['ip']})", "High")

    # --- Rule 2: session-level periodicity -> heartbeat -------------------
    sess = safe_read(f"{tab_dir}/{device}_session_periodicity.csv")
    for _, row in sess.iterrows():
        if row.get("classification") == "heartbeat/periodic (session-level)":
            add(0, f"{int(row['num_connections'])} connections to {row['remote_endpoint']}, "
                   f"mean interval {row['mean_interval_s']}s (CV={row['cv']})",
                int(row["num_connections"]), "TCP/TLS",
                "Low coefficient of variation in inter-connection intervals indicates a "
                "programmatically scheduled check-in rather than user-driven activity.",
                f"Heartbeat / background cloud synchronisation with {row['remote_endpoint']}", "High")

    # --- Rule 3: DNS classification -> cloud service resolution ----------
    dns_class = safe_read(f"{tab_dir}/{device}_dns_cloud_classification.csv", index_col=0)
    for cat, row in dns_class.iterrows():
        if cat in ("Unclassified / other",):
            continue
        add(0, f"{int(row.iloc[0])} DNS/TLS-SNI records classified as {cat}", int(row.iloc[0]),
            "DNS / TLS SNI",
            "Hostname matches a known vendor or cloud/CDN domain pattern, indicating the "
            "device or its traffic is served by that provider.",
            f"Cloud service contact: {cat}", "Medium")

    # --- Rule 4: JA3 diversity -> distinct client software components ----
    ja3 = safe_read(f"{tab_dir}/{device}_ja3_fingerprints.csv")
    if not ja3.empty:
        n_distinct = ja3["ja3_hash"].nunique()
        dominant = ja3["ja3_hash"].value_counts()
        add(0, f"{len(ja3)} TLS ClientHellos, {n_distinct} distinct JA3 fingerprints "
               f"(dominant: {dominant.index[0]} x{dominant.iloc[0]})", len(ja3), "TLS (ClientHello)",
            "A single JA3 fingerprint reused across many destination IPs indicates one "
            "underlying TLS client implementation drives most cloud communication; "
            "additional distinct fingerprints indicate separate software components/libraries "
            "on the device making independent TLS connections.",
            f"Device TLS-stack fingerprinting ({n_distinct} distinct client profiles)", "Medium")

    # --- Rule 5/6/7: traffic-state segmentation -> burst / idle events ---
    seg = safe_read(f"{tab_dir}/{device}_traffic_state_segmentation.csv")
    if not seg.empty:
        seg = seg.rename(columns={seg.columns[0]: "bin"})
        runs = merge_runs(seg)
        flow_summary = safe_read(f"{tab_dir}/{device}_flow_summary.csv")
        for state, start, end, packets in runs:
            duration = end - start
            if state == "burst":
                # Try to identify the dominant endpoint driving this burst via top conversations
                conv = safe_read(f"{tab_dir}/{device}_top_conversations.csv")
                dom_ep = conv.iloc[0]["ip.dst"] if not conv.empty and "ip.dst" in conv.columns else "unknown"

                # Cross-reference: was a named DNS/SNI hostname resolved shortly
                # before/during this burst that corroborates a specific cause?
                nearby = nearby_hostnames(named_events, start, end)
                update_hit = next((h for h in nearby if any(k in h.lower() for k in UPDATE_KEYWORDS)), None)
                voice_hit = next((h for h in nearby if any(k in h.lower() for k in VOICE_KEYWORDS)), None)

                if duration >= 60 and update_hit:
                    reasoning = (
                        f"Sustained high packet-rate window (z-score threshold exceeded for a "
                        f"continuous run) immediately preceded/accompanied by a DNS or TLS-SNI "
                        f"lookup for '{update_hit}', a hostname matching a known "
                        f"software/firmware-update naming pattern. The named-service lookup "
                        f"directly preceding a large sustained transfer is treated as corroborating "
                        f"evidence, not volume/timing alone."
                    )
                    activity = f"Likely software/firmware update (corroborated by DNS/SNI lookup: {update_hit})"
                    confidence = "High"
                elif duration >= 60 and voice_hit:
                    reasoning = (
                        f"Sustained high packet-rate window immediately preceded/accompanied by a "
                        f"DNS or TLS-SNI lookup for '{voice_hit}', a hostname matching a known "
                        f"voice/speech-service naming pattern. The named-service lookup is treated "
                        f"as corroborating evidence for a voice interaction beyond volume/timing alone."
                    )
                    activity = f"Likely voice/audio interaction (corroborated by DNS/SNI lookup: {voice_hit})"
                    confidence = "High"
                elif duration >= 60:
                    reasoning = (
                        "Sustained high packet-rate window well above the capture's baseline "
                        "rate (z-score threshold exceeded for a continuous run). Duration and "
                        "volume are consistent with either a real-time media/voice session or a "
                        "bulk data transfer (e.g. firmware/software update); no corroborating "
                        "DNS/SNI hostname naming a specific service was found nearby, so packet "
                        "timing and volume alone cannot disambiguate between these without "
                        "payload access."
                    )
                    activity = "Possible user interaction (voice/audio session) or bulk data transfer (e.g. firmware update)"
                    confidence = "Medium"
                else:
                    reasoning = (
                        "Short-duration packet-rate spike above baseline. Consistent with a "
                        "single short interaction, a status poll response, or a brief control "
                        "message exchange."
                    )
                    activity = "Possible short user interaction or control-message exchange"
                    confidence = "Low"
                    if voice_hit:
                        reasoning += (f" A nearby DNS/SNI lookup for '{voice_hit}' (voice/speech-service "
                                      "naming pattern) suggests this may be a brief voice interaction.")
                        activity = f"Possible brief voice interaction (nearby DNS/SNI lookup: {voice_hit})"
                        confidence = "Medium"
                add(start, f"Burst: {int(packets)} packets over {duration:.0f}s, dominant endpoint {dom_ep}",
                    int(packets), "Mixed (see top conversation)", reasoning, activity, confidence)
            elif state == "idle" and duration >= 120:
                add(start, f"Idle interval: {duration:.0f}s with only {int(packets)} packets",
                    int(packets), "Background/keepalive only",
                    "Packet rate at or below baseline for a sustained period indicates no "
                    "active user interaction; only incidental background traffic present.",
                    "Idle state", "High")

    # --- Rule 8: meta-periodicity of burst events themselves --------------
    # A set of short bursts that recur at a fairly regular cadence across the
    # whole capture is better explained as scheduled polling than as
    # independent, sporadic user interactions; re-score accordingly.
    burst_idx = [i for i, e in enumerate(events) if e["likely_activity"].startswith(
        "Possible short user interaction")]
    if len(burst_idx) >= 5:
        burst_times = np.array(sorted(events[i]["time_s"] for i in burst_idx))
        iat = np.diff(burst_times)
        cv = iat.std() / iat.mean() if iat.mean() > 0 else np.inf
        if cv < 0.6:
            for i in burst_idx:
                events[i]["reasoning"] += (
                    f" Additionally, this burst is one of {len(burst_idx)} short bursts recurring "
                    f"at a fairly regular cadence (mean interval {iat.mean():.0f}s, CV={cv:.2f}) "
                    "across the full capture duration, which is better explained by scheduled "
                    "polling than by independent, sporadic user interaction."
                )
                events[i]["likely_activity"] = "Regular short-burst pattern (likely scheduled polling / periodic status exchange)"
                events[i]["confidence"] = "Medium"

    timeline = pd.DataFrame(events).sort_values(["time_s", "confidence"])
    timeline.insert(0, "event_id", [f"{device.upper()}-{i+1:03d}" for i in range(len(timeline))])
    timeline.to_csv(f"{res_dir}/{device}_forensic_timeline.csv", index=False)

    conf_counts = timeline["confidence"].value_counts().reindex(["High", "Medium", "Low"]).fillna(0).astype(int)
    print(f"[{device}] {len(timeline)} forensic events reconstructed "
          f"(High={conf_counts.get('High',0)}, Medium={conf_counts.get('Medium',0)}, Low={conf_counts.get('Low',0)})")


if __name__ == "__main__":
    main()
