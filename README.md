# Network-Only Forensic Reconstruction of Smart-Home IoT Activity from Public PCAP Corpora

MSc dissertation project artefact: a reusable, rule-based **Network-Only Forensic Reconstruction Framework** that reconstructs smart-home IoT device activity from network packet captures alone — no device logs, no cloud records, no payload decryption. The framework is implemented as a twelve-stage Python/tshark pipeline and demonstrated against three real-hardware, benign device captures from the [IoT-23 dataset](https://www.stratosphereips.org/datasets-iot23) (Stratosphere Laboratory, CTU): a Philips Hue smart bulb, an Amazon Echo, and a Somfy door-lock gateway.

Every stage — packet extraction, device identification, DNS/TLS/JA3 analysis, traffic-state segmentation, and a rule-based activity-reconstruction engine with an explicit High/Medium/Low confidence policy — is implemented as an independent, reusable script operating on any conforming pcap file. This repository contains the complete implementation and all generated evidence (tables, figures, forensic timelines); it does not contain the dissertation write-up itself or the raw pcap evidence files (see [Obtaining the Dataset](#obtaining-the-dataset) for why, and how to get them).

## Table of Contents

- [Repository Structure](#repository-structure)
- [Key Outputs at a Glance](#key-outputs-at-a-glance)
- [Prerequisites](#prerequisites)
- [Setup — Linux](#setup--linux)
- [Setup — Windows](#setup--windows)
- [Obtaining the Dataset](#obtaining-the-dataset)
- [Running the Pipeline](#running-the-pipeline)
- [Pipeline Stages, In Order](#pipeline-stages-in-order)
- [Understanding the Outputs](#understanding-the-outputs)
- [Known Data Quality Note](#known-data-quality-note)
- [Reproducibility](#reproducibility)
- [Troubleshooting](#troubleshooting)
- [License and Attribution](#license-and-attribution)

---

## Repository Structure

```
IoT_Forensics/
├── README.md                 This file
├── requirements.txt           Python dependencies
├── scripts/                   Full pipeline implementation (13 scripts)
├── pcaps/                     NOT included — see "Obtaining the Dataset"
├── Results/                   Forensic timelines (CSV/Excel/Markdown/PNG formats).
│                               Per-device *_full.csv extraction files are
│                               gitignored (regenerable, ~4–77MB each) — running
│                               the pipeline recreates them locally.
├── Tables/                    72 generated CSV tables (device inventory, DNS
│                               classification, TLS certificates, JA3 fingerprints,
│                               periodicity, cross-device comparison, …)
├── Figures/                   120 generated figures (PNG @300dpi + SVG), 60 per
│                               device × 3 devices, plus cross-device comparisons
└── Screenshots/               tshark-generated Protocol Hierarchy / Conversations /
                                Endpoints statistical exports (see note in scripts)
```

## Key Outputs at a Glance

- **`Results/<device>_forensic_timeline.csv`** (also `.xlsx`, `.md`, `.png`) — the actual reconstructed, confidence-scored activity timeline per device. This is the primary output of the framework.
- **`Tables/comparison_device_summary.csv`** — cross-device behavioural comparison.
- **`Tables/echo_tls_certificates.csv`**, **`Tables/echo_ja3_fingerprints.csv`** — recovered TLS certificate metadata and JA3 client fingerprints.

## Prerequisites

| Tool | Minimum version | Purpose |
|---|---|---|
| [Wireshark / tshark](https://www.wireshark.org/download.html) | 3.2+ (tested on 3.2.3) | Packet dissection and field extraction |
| [Python](https://www.python.org/downloads/) | 3.9+ (tested on 3.11.13) | All analysis, statistics, and figure generation |
| `pip` | any recent | Python package installation |
| A POSIX-style shell (bash) | — | Running `extract_full.sh` / `run_all.sh` — see [Setup — Windows](#setup--windows) for how to get one on Windows |

No GPU, no internet access at run time (beyond the initial dataset download and one best-effort IP-organisation lookup in `dns_analysis.py`, which fails gracefully if offline).

---

## Setup — Linux

Tested on Ubuntu 20.04/22.04; equivalent for other Debian-based distributions. For non-Debian distributions, substitute your package manager (`dnf`, `pacman`, etc.) for `apt`.

```bash
# 1. Update package lists
sudo apt update

# 2. Install Wireshark/tshark
sudo apt install -y wireshark tshark
# During install you may be asked "Should non-superusers be able to capture
# packets?" — answer is irrelevant for this project, since it only reads
# existing pcap files and performs no live capture.

# 3. Verify tshark is on PATH
tshark -v

# 4. Verify Python 3.9+ is available
python3 --version

# 5. Clone this repository
git clone <your-repository-url>
cd IoT_Forensics

# 6. Install Python dependencies (user-level install, no sudo needed)
pip3 install --user -r requirements.txt

# 7. Make the shell scripts executable
chmod +x scripts/*.sh

# 8. Obtain the dataset — see "Obtaining the Dataset" below — then run the pipeline
./scripts/run_all.sh
```

---

## Setup — Windows

The pipeline's orchestration scripts (`run_all.sh`, `extract_full.sh`) are bash shell scripts. Windows has no native bash, so **Windows Subsystem for Linux (WSL2) is the recommended path** — it gives you an identical environment to the Linux instructions above, avoids maintaining a second command set, and every script in this repository will behave exactly as tested. A lighter-weight Git Bash alternative is given as Option B for anyone who does not want to install WSL2.

### Option A — WSL2 (recommended)

```powershell
# 1. In an elevated PowerShell, install WSL2 with Ubuntu (one-time; requires a reboot)
wsl --install -d Ubuntu

# 2. After reboot, launch "Ubuntu" from the Start menu and create a UNIX
#    username/password when prompted. You are now in a real Linux shell.
```

From here, **follow the entire [Setup — Linux](#setup--linux) section above, inside the WSL2 Ubuntu terminal.** Your Windows filesystem is available inside WSL2 at `/mnt/c/...` if you want to place the repository on the Windows side, but cloning directly into the Linux filesystem (e.g. `~/IoT_Forensics`) will run noticeably faster for the packet-extraction stages.

To open the repository folder in a Windows GUI text editor (e.g. VS Code) while working from WSL2:

```bash
# from inside the WSL2 Ubuntu terminal, in the repo directory
code .
```

### Option B — Native Windows with Git Bash

Use this only if you cannot install WSL2 (e.g. a locked-down managed machine).

```powershell
# 1. Install Wireshark for Windows (includes tshark.exe)
#    Download from https://www.wireshark.org/download.html and run the installer.
#    During install, ensure "Install TShark" is checked (it is, by default).

# 2. Add Wireshark's install directory to your PATH so `tshark` is found from
#    any terminal. Default install location:
#      C:\Program Files\Wireshark
#    System Properties -> Advanced -> Environment Variables -> Path -> New
#    -> add "C:\Program Files\Wireshark", then restart your terminal.

# 3. Verify tshark is found
tshark -v

# 4. Install Python 3.9+ from https://www.python.org/downloads/
#    IMPORTANT: tick "Add python.exe to PATH" on the first installer screen.

# 5. Verify Python
python --version

# 6. Install Git for Windows (https://git-scm.com/download/win), which bundles
#    Git Bash — a bash-compatible shell capable of running .sh scripts on Windows.

# 7. Clone the repository (in Git Bash or PowerShell)
git clone <your-repository-url>
cd IoT_Forensics

# 8. Install Python dependencies
pip install -r requirements.txt

# 9. Run the pipeline from Git Bash specifically (not PowerShell/cmd, which
#    cannot execute .sh scripts directly)
bash scripts/run_all.sh
```

**Known Git Bash caveats:** Git Bash's Python invocation sometimes resolves to the wrong interpreter if multiple Python versions are installed — if `python3` is not found inside Git Bash, edit `scripts/run_all.sh` and replace `python3` with `python` (Windows' launcher name), or run the pipeline stage-by-stage substituting `python` for `python3` as shown in [Running the Pipeline](#running-the-pipeline).

---

## Obtaining the Dataset

The three `.pcap` evidence files are **not included in this repository** and must be downloaded directly from the Stratosphere Laboratory's public mirror, under IoT-23's own open licence — this project does not redistribute them. This also means the download step re-verifies the exact evidence used in the original analysis, which is itself part of the forensic evidence-verification stage documented in the project's methodology.

Create the `pcaps/` directory and download the three individual scenario captures:

**Linux / macOS / WSL2 / Git Bash:**
```bash
mkdir -p pcaps
BASE="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios"

curl -o pcaps/hue_2018-10-25.pcap.xz \
  "$BASE/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz"
unxz -k pcaps/hue_2018-10-25.pcap.xz

curl -o pcaps/echo_2018-09-21.pcap \
  "$BASE/CTU-Honeypot-Capture-5-1/2018-09-21-capture.pcap"

curl -o pcaps/somfy_2019-07-03.pcap \
  "$BASE/CTU-Honeypot-Capture-7-1/Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap"
```

**Native Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path pcaps | Out-Null
$base = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios"

Invoke-WebRequest "$base/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz" -OutFile pcaps\hue_2018-10-25.pcap.xz
# .xz decompression: install 7-Zip (https://www.7-zip.org/) and extract via its GUI,
# or `wsl unxz pcaps/hue_2018-10-25.pcap.xz` if you have WSL available.

Invoke-WebRequest "$base/CTU-Honeypot-Capture-5-1/2018-09-21-capture.pcap" -OutFile pcaps\echo_2018-09-21.pcap

Invoke-WebRequest "$base/CTU-Honeypot-Capture-7-1/Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap" -OutFile pcaps\somfy_2019-07-03.pcap
```

Expect roughly 4.4 MB (Hue), 364 MB (Echo), and 2 MB (Somfy) after decompression — the Echo download is the slow one. Verify integrity by comparing the downloaded byte count against each URL's `Content-Length` header (e.g. `curl -sI <url> | grep -i content-length`), consistent with the evidence-verification step this project's methodology documents.

---

## Running the Pipeline

### Option 1 — One command, everything

```bash
./scripts/run_all.sh
```

This runs full extraction and every analysis stage for all three devices, then the cross-device comparison, writing into `Results/`, `Tables/`, `Figures/` and `Screenshots/`. Expect this to take several minutes, dominated by the Echo capture's TLS/JA3 stage (the largest capture, ~400,000 packets).

### Option 2 — Stage by stage (for understanding or partial re-runs)

Substitute `<device>` with `hue`, `echo`, or `somfy`, and `<pcap>` with the corresponding file in `pcaps/`. On native Windows (Option B above), replace `python3` with `python`.

```bash
# 1. Full-fidelity field extraction
./scripts/extract_full.sh pcaps/<pcap> Results/<device>_full.csv

# 2. Device identification (MAC/OUI, broadcast/multicast classification)
python3 scripts/device_id.py <device> Results/<device>_full.csv Tables

# 3. Traffic statistics (protocol, flow, port, conversation, endpoint analysis)
python3 scripts/traffic_stats.py <device> Results/<device>_full.csv Figures Tables

# 4. DNS / cloud-provider classification
python3 scripts/dns_analysis.py <device> Results/<device>_full.csv Figures Tables

# 5. TLS analysis, JA3 fingerprinting, certificate recovery
python3 scripts/tls_analysis.py <device> pcaps/<pcap> Results/<device>_full.csv Figures Tables

# 6. Idle/burst/heartbeat traffic-state segmentation
python3 scripts/flow_periodicity.py <device> Results/<device>_full.csv Figures Tables

# 7. Rule-based activity reconstruction (the core framework output)
python3 scripts/activity_engine.py <device> Tables Results Results/<device>_full.csv

# 8. tshark Statistics-menu equivalent exports
python3 scripts/stats_exports.py <device> pcaps/<pcap> Screenshots

# 9. Export the forensic timeline in CSV/Excel/Markdown/PNG
python3 scripts/export_timeline_formats.py <device> Results

# --- Run once, after all three devices have been processed above ---

# 10. Cross-device comparison
python3 scripts/comparison.py Tables Results Figures
```

---

## Pipeline Stages, In Order

| # | Script | Stage | Produces |
|---|---|---|---|
| 1 | `extract_full.sh` | Packet extraction | Structured per-packet CSV (Ethernet/IP/transport/DNS/TLS fields) |
| 2 | `device_id.py` | Device identification | MAC/manufacturer inventory, broadcast/multicast classification |
| 3 | `traffic_stats.py` | Protocol & flow analysis | Protocol mix, flow duration, port usage, top conversations/endpoints |
| 4 | `dns_analysis.py` | DNS analysis | Cloud/CDN classification of queried domains |
| 5 | `tls_analysis.py` | TLS/JA3 analysis | TLS version distribution, JA3 client fingerprints, recovered certificates |
| 6 | `flow_periodicity.py` | Behavioural segmentation | Idle/burst/heartbeat traffic-state classification |
| 7 | `activity_engine.py` | **Activity reconstruction (the framework's core)** | Confidence-scored forensic timeline |
| 8 | `stats_exports.py` | Statistical exports | Protocol Hierarchy / Conversations / Endpoints (tshark `-z` statistics) |
| 9 | `export_timeline_formats.py` | Timeline export | CSV/Excel/Markdown/PNG versions of the forensic timeline |
| 10 | `comparison.py` | Cross-device comparison | Aggregated comparison tables and figures across all devices |

Two additional scripts (`extract_fields.sh`, `analyze.py`) implement an earlier, simpler prototype extraction/analysis pass retained for reference; they are not part of the primary pipeline documented above and are not invoked by `run_all.sh`.

## Understanding the Outputs

- **Confidence ratings** (`High` / `Medium` / `Low`) in the forensic timelines follow a fixed, declared policy defined in `activity_engine.py`: High confidence requires either protocol-definitional certainty (e.g. SSDP/mDNS discovery traffic) or corroboration by two or more independent evidence signals (e.g. a traffic burst plus a specifically-matching DNS lookup); Medium confidence reflects a single consistent signal; Low confidence reflects weak or small-sample evidence. This policy is fixed in the code and is not tuned per device.
- **No activity-level ground truth exists** for the IoT-23 dataset used here — its labels address malware/benign classification, not user-activity annotation. Accordingly, this project does not compute or report accuracy/precision/recall/F1 against any ground truth; the confidence policy above is the intended substitute evaluation mechanism, and this distinction is important when interpreting any of the generated tables.
- **`Tables/`** filenames follow the pattern `<device>_<analysis-type>.csv` throughout.
- **`Figures/`** are generated at 300dpi (PNG) plus vector SVG for every chart.

## Known Data Quality Note

The Amazon Echo source pcap (`echo_2018-09-21.pcap`) is truncated mid-packet at its final frame — a property of the original file on the source server, not a download or extraction defect (verified by an exact byte-count match against the server's declared `Content-Length`). `tshark` reports this as a non-fatal warning; `extract_full.sh` is written not to treat this as a pipeline failure, since doing so would discard the ~398,000 valid preceding packets over the loss of one incomplete trailing frame. You will see this warning printed during extraction — it is expected and does not indicate a problem with your setup.

## Reproducibility

Every stage of this pipeline is deterministic, version-controlled source code with no external service dependency at analysis time (the one exception, a best-effort IP-organisation lookup in `dns_analysis.py`, fails gracefully offline and does not affect any of the framework's core forensic conclusions). Re-running `run_all.sh` against the same downloaded evidence files will reproduce byte-identical CSV outputs and visually identical figures.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `tshark: command not found` | tshark is not on your PATH. Linux: `sudo apt install tshark`. Windows: add `C:\Program Files\Wireshark` to PATH and restart your terminal. |
| `ModuleNotFoundError` for pandas/numpy/matplotlib/cryptography/openpyxl/tabulate | Run `pip install -r requirements.txt` (or `pip3 install --user -r requirements.txt` on Linux). |
| `run_all.sh: Permission denied` | Run `chmod +x scripts/*.sh` first (Linux/WSL2/Git Bash). |
| `.sh` scripts don't run in PowerShell/cmd | PowerShell/cmd cannot execute bash scripts directly. Use WSL2 (Option A) or Git Bash (Option B) — see [Setup — Windows](#setup--windows). |
| Extraction produces a "cut short in the middle of a packet" warning for the Echo capture | Expected — see [Known Data Quality Note](#known-data-quality-note) above. Not an error. |
| `dns_analysis.py` hangs or is slow | The best-effort IP-organisation lookup step is network-bound; if you're offline or the lookup service is unreachable, it will time out per-IP (a few seconds each) rather than fail outright. This does not affect the pipeline's core output. |
| `SettingWithCopyWarning` printed during `dns_analysis.py` | A harmless pandas warning, not an error; the script completes and produces correct output. |

## License and Attribution

This repository contains original implementation code produced for an MSc dissertation project. The evidence dataset (IoT-23) is © Stratosphere Laboratory, CTU University, and is not redistributed here — see [Obtaining the Dataset](#obtaining-the-dataset) to source it directly under its own licence terms at <https://www.stratosphereips.org/datasets-iot23>.
