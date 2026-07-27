#!/usr/bin/env python3
"""
Part 5 - TLS analysis: versions, cipher suites, SNI, certificates, JA3.

TLS record version / SNI hostnames are read directly from the full-fields
CSV. Cipher suite lists, extension order and elliptic-curve parameters are
not reliably exposed by tshark's `-T fields` mode for repeated/nested
fields, so ClientHello packets (typically few dozen per capture) are
re-parsed individually via `tshark -V` verbose decode and a JA3 fingerprint
(Al Naji et al. algorithm, MD5 of Version,Ciphers,Extensions,Curves,
PointFormats, GREASE values excluded per RFC 8701) is computed directly
from the packet contents -- no external JA3 database or fingerprint
lookup service is used, so this is a client-parameter fingerprint only,
not identity attribution.

Certificates are extracted and parsed (subject, issuer, validity) only
where sent in cleartext, i.e. TLS <=1.2 full handshakes; TLS 1.3 encrypts
the Certificate message and it will not be recoverable here.

Usage: python3 tls_analysis.py <device> <pcap> <full.csv> <figures_dir> <tables_dir>
"""
import sys
import re
import hashlib
import subprocess
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from cryptography import x509
from cryptography.hazmat.backends import default_backend

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

VERSION_LABEL = {
    "0x00000300": "SSL 3.0", "0x00000301": "TLS 1.0", "0x00000302": "TLS 1.1",
    "0x00000303": "TLS 1.2", "0x00000304": "TLS 1.3",
}


def hexes(pattern, text):
    return [int(h, 16) for h in re.findall(pattern, text)]


def parse_clienthello_block(text):
    """Parse one tshark -V decoded ClientHello block, return JA3 components."""
    # Handshake (inner) version = second "Version: TLS x.x (0xXXXX)" occurrence
    versions = re.findall(r"Version: TLS [\d.]+ \(0x([0-9a-f]+)\)", text)
    hs_version = int(versions[1], 16) if len(versions) > 1 else (int(versions[0], 16) if versions else 0)

    ciphers = hexes(r"Cipher Suite: [\w_]+ \(0x([0-9a-f]{4})\)", text)

    # Extension type order: lines that start with "Type: name (N)" directly under an Extension block
    ext_types = [int(n) for n in re.findall(r"^\s*Type: [\w\-]+ \((\d+)\)\s*$", text, re.MULTILINE)]

    curves = []
    m = re.search(r"Extension: supported_groups.*?(?=\n\s{0,16}Extension: |\Z)", text, re.DOTALL)
    if m:
        curves = hexes(r"\(0x([0-9a-f]{4})\)", m.group(0))

    point_formats = []
    m = re.search(r"Extension: ec_point_formats.*?(?=\n\s{0,16}Extension: |\Z)", text, re.DOTALL)
    if m:
        point_formats = [int(n) for n in re.findall(r"EC point format: [\w\-]+ \((\d+)\)", m.group(0))]

    ciphers = [c for c in ciphers if c not in GREASE]
    ext_types = [e for e in ext_types if e not in GREASE]
    curves = [c for c in curves if c not in GREASE]

    ja3_str = "{},{},{},{},{}".format(
        hs_version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_types),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    )
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
    return {
        "handshake_version": hex(hs_version),
        "num_ciphers": len(ciphers),
        "num_extensions": len(ext_types),
        "ja3_string": ja3_str,
        "ja3_hash": ja3_hash,
    }


def compute_ja3_fingerprints(device, pcap, tab_dir):
    meta = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tls.handshake.type==1", "-T", "fields",
         "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "frame.time_epoch"],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()
    meta_by_frame = {}
    for line in meta:
        parts = line.split("\t")
        if len(parts) >= 4:
            meta_by_frame[parts[0]] = {"time": parts[3], "src": parts[1], "dst": parts[2]}

    # Single-pass verbose dump of every ClientHello packet, split on frame boundaries.
    verbose = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tls.handshake.type==1", "-V"],
        capture_output=True, text=True,
    ).stdout
    blocks = re.split(r"(?=^Frame \d+:)", verbose, flags=re.MULTILINE)

    rows = []
    for block in blocks:
        fm = re.match(r"^Frame (\d+):", block)
        if not fm:
            continue
        fno = fm.group(1)
        m = re.search(r"Handshake Protocol: Client Hello.*", block, re.DOTALL)
        if not m:
            continue
        parsed = parse_clienthello_block(m.group(0))
        info = meta_by_frame.get(fno, {})
        rows.append({"frame": fno, **info, **parsed})

    df = pd.DataFrame(rows)
    df.to_csv(f"{tab_dir}/{device}_ja3_fingerprints.csv", index=False)
    return df


def certificate_analysis(device, csv_path, tab_dir):
    df = pd.read_csv(csv_path, dtype=str)
    certs = df.dropna(subset=["tls.handshake.certificate"])
    rows = []
    for _, row in certs.iterrows():
        raw = row["tls.handshake.certificate"]
        try:
            der = bytes.fromhex(raw.split(",")[0])
            cert = x509.load_der_x509_certificate(der, default_backend())
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            rows.append({
                "frame": row["frame.number"],
                "dst_ip": row.get("ip.dst"),
                "subject_cn": cn[0].value if cn else None,
                "issuer_cn": issuer_cn[0].value if issuer_cn else None,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "serial": str(cert.serial_number),
            })
        except Exception as e:
            rows.append({"frame": row["frame.number"], "dst_ip": row.get("ip.dst"),
                          "parse_error": str(e)})
            continue
    cert_df = pd.DataFrame(rows).drop_duplicates(subset=["subject_cn", "serial"])
    cert_df.to_csv(f"{tab_dir}/{device}_tls_certificates.csv", index=False)
    return cert_df


def main():
    device, pcap, csv_path, fig_dir, tab_dir = sys.argv[1:6]
    df = pd.read_csv(csv_path, dtype=str)

    # TLS version distribution (record layer)
    versions = df["tls.record.version"].dropna().map(lambda v: VERSION_LABEL.get(v, v)).value_counts()
    versions.to_csv(f"{tab_dir}/{device}_tls_version_distribution.csv", header=["record_count"])
    if not versions.empty:
        fig, ax = plt.subplots(figsize=(6, 4))
        versions.plot(kind="bar", ax=ax, color="#4C72B0")
        ax.set_title(f"{device.capitalize()}: TLS Record Version Distribution")
        ax.set_xlabel("TLS version"); ax.set_ylabel("Record count")
        fig.savefig(f"{fig_dir}/{device}_tls_version_distribution.png", dpi=300, bbox_inches="tight")
        fig.savefig(f"{fig_dir}/{device}_tls_version_distribution.svg", bbox_inches="tight")
        plt.close(fig)

    # SNI hostnames
    sni = df["tls.handshake.extensions_server_name"].dropna().value_counts()
    sni.to_csv(f"{tab_dir}/{device}_tls_sni_hostnames.csv", header=["handshake_count"])

    # JA3
    ja3_df = compute_ja3_fingerprints(device, pcap, tab_dir)

    # Certificates
    cert_df = certificate_analysis(device, csv_path, tab_dir)

    print(f"[{device}] TLS records: {versions.sum() if not versions.empty else 0}, "
          f"SNI hosts: {len(sni)}, ClientHellos parsed: {len(ja3_df)}, "
          f"distinct JA3: {ja3_df['ja3_hash'].nunique() if len(ja3_df) else 0}, "
          f"certificates recovered: {len(cert_df)}")
    if len(ja3_df):
        print(ja3_df[["src", "dst", "ja3_hash", "num_ciphers", "num_extensions"]].to_string(index=False))


if __name__ == "__main__":
    main()
