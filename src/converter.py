"""
Phase 2 - Dataset preparation.

Reads the CICIDS2017 labelled flow CSVs (GeneratedLabelledFlows / TrafficLabelling),
groups flows into attack episodes, samples a balanced evaluation set and converts
every episode into the three artefacts required by the project brief:

    1. a SIEM alert            (Wazuh-style JSON)
    2. an incident report      (narrative text)
    3. an investigation note   (preliminary analyst note)

Ground truth (label, attack class, accepted MITRE ATT&CK techniques, reference
severity and reference remediation) is stored separately from what the model sees.

Output:  data/clean/alerts.jsonl   and   data/clean/sample_summary.txt
"""

import argparse
import csv
import glob
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (CLEAN_DIR, GROUND_TRUTH, LABEL_TO_CLASS, PROTO, RAW_DIR,  # noqa: E402
                    SERVICE_BY_PORT, load_config, write_jsonl)

csv.field_size_limit(10_000_000)

NEEDED = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol",
          "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
          "Total Length of Fwd Packets", "Total Length of Bwd Packets", "SYN Flag Count", "Label"]

COMMON_BENIGN_PORTS = {53, 80, 443, 22, 21, 123, 445, 8080, 139, 389, 88}


def normalise_label(raw):
    s = raw.strip()
    if s.lower().startswith("web attack"):
        low = s.lower()
        if "brute" in low:
            return "Web Attack - Brute Force"
        if "xss" in low:
            return "Web Attack - XSS"
        if "sql" in low:
            return "Web Attack - Sql Injection"
    return s


def to_num(x):
    try:
        return float(x)
    except Exception:
        return 0.0


def find_csvs():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "**", "*.csv"), recursive=True))
    if not files:
        print("No CSV files found in", RAW_DIR)
        print("Download GeneratedLabelledFlows.zip from CICIDS2017 and extract it there.")
        sys.exit(1)
    return files


def aggregate(files):
    """Group flows into episodes. Attacks: (label, src, dst). Benign: (src, dst, dport)."""
    groups = {}
    monday = [f for f in files if "monday" in os.path.basename(f).lower()]
    benign_files = set(monday or files[:1])
    rows_read = 0
    for path in files:
        name = os.path.basename(path)
        with open(path, encoding="latin-1", newline="") as f:
            reader = csv.reader(f)
            header = [h.strip().lstrip("﻿") for h in next(reader)]
            idx = {}
            for i, h in enumerate(header):
                idx.setdefault(h, i)
            missing = [c for c in NEEDED if c not in idx]
            if missing:
                print(f"  skipping {name}: missing columns {missing}")
                continue
            print(f"  reading {name} ...", flush=True)
            for row in reader:
                if len(row) <= idx["Label"]:
                    continue
                label = normalise_label(row[idx["Label"]])
                cls = LABEL_TO_CLASS.get(label)
                if cls is None:
                    continue
                rows_read += 1
                src = row[idx["Source IP"]].strip()
                dst = row[idx["Destination IP"]].strip()
                try:
                    dport = int(float(row[idx["Destination Port"]]))
                except Exception:
                    continue
                if cls == "Benign":
                    if path not in benign_files:
                        continue
                    key = ("BENIGN", src, dst, dport)
                else:
                    key = (label, src, dst, None)
                g = groups.get(key)
                ts = row[idx["Timestamp"]].strip()
                if g is None:
                    g = {"label": label, "cls": cls, "src": src, "dst": dst, "n": 0,
                         "first": ts, "last": ts, "fwd_p": 0, "bwd_p": 0, "fwd_b": 0,
                         "bwd_b": 0, "dur": 0.0, "syn": 0, "ports": Counter(),
                         "proto": Counter(), "samples": [], "file": name}
                    groups[key] = g
                g["n"] += 1
                g["last"] = ts
                g["fwd_p"] += int(to_num(row[idx["Total Fwd Packets"]]))
                g["bwd_p"] += int(to_num(row[idx["Total Backward Packets"]]))
                g["fwd_b"] += int(to_num(row[idx["Total Length of Fwd Packets"]]))
                g["bwd_b"] += int(to_num(row[idx["Total Length of Bwd Packets"]]))
                g["dur"] += to_num(row[idx["Flow Duration"]])
                g["syn"] += int(to_num(row[idx["SYN Flag Count"]]))
                if len(g["ports"]) < 5000 or dport in g["ports"]:
                    g["ports"][dport] += 1
                g["proto"][PROTO.get(row[idx["Protocol"]].strip(), row[idx["Protocol"]].strip())] += 1
                if len(g["samples"]) < 3:
                    g["samples"].append(
                        f"{ts} {src}:{row[idx['Source Port']].strip()} -> {dst}:{dport} "
                        f"{PROTO.get(row[idx['Protocol']].strip(), 'proto')} "
                        f"dur={int(to_num(row[idx['Flow Duration']]))}us "
                        f"pkts={int(to_num(row[idx['Total Fwd Packets']]))}/"
                        f"{int(to_num(row[idx['Total Backward Packets']]))} "
                        f"bytes={int(to_num(row[idx['Total Length of Fwd Packets']]))}/"
                        f"{int(to_num(row[idx['Total Length of Bwd Packets']]))}")
    print(f"  flows read: {rows_read:,}   episodes: {len(groups):,}")
    return groups


def select(groups, per_class, n_benign, seed):
    rng = random.Random(seed)
    chosen = []
    classes = [c for c in GROUND_TRUTH if c != "Benign"]
    for cls in classes:
        cands = [g for g in groups.values() if g["cls"] == cls and g["n"] >= 5]
        cands.sort(key=lambda g: -g["n"])
        picked, seen_labels = [], set()
        for g in cands:                      # prefer different original labels first
            if g["label"] not in seen_labels:
                picked.append(g)
                seen_labels.add(g["label"])
            if len(picked) == per_class:
                break
        for g in cands:                      # then fill with the largest remaining
            if len(picked) == per_class:
                break
            if g not in picked:
                picked.append(g)
        if len(picked) < per_class:
            print(f"  warning: only {len(picked)} episodes available for {cls}")
        chosen += picked
    benign = [g for g in groups.values() if g["cls"] == "Benign" and g["n"] >= 20
              and next(iter(g["ports"])) in COMMON_BENIGN_PORTS]
    rng.shuffle(benign)
    by_port, out = {}, []
    for g in benign:                         # spread benign alerts over services
        p = next(iter(g["ports"]))
        if by_port.get(p, 0) < 2:
            out.append(g)
            by_port[p] = by_port.get(p, 0) + 1
        if len(out) == n_benign:
            break
    return chosen + out


def is_internal(ip):
    return ip.startswith("192.168.") or ip.startswith("10.")


def build_alert(g, n):
    top_port, _ = g["ports"].most_common(1)[0]
    distinct = len(g["ports"])
    svc = SERVICE_BY_PORT.get(top_port, "unknown")
    proto = g["proto"].most_common(1)[0][0]
    avg_ms = round(g["dur"] / max(g["n"], 1) / 1000, 2)

    # Rule description is derived from traffic features, service and direction only
    # (never from the dataset label), like a real SIEM correlation rule.
    internal_src, internal_dst = is_internal(g["src"]), is_internal(g["dst"])
    if distinct >= 50:
        desc = f"Possible port scan: single source contacted {distinct} distinct destination ports on one host"
        level = 8
    elif svc in ("ssh", "ftp", "telnet", "rdp") and g["n"] >= 100:
        desc = (f"Possible brute-force authentication attempts: {g['n']} connections "
                f"to {svc}/{top_port} from a single source")
        level = 10
    elif internal_src and not internal_dst and svc in ("http", "http-alt", "https") and g["n"] >= 100:
        desc = (f"Possible command-and-control beaconing: {g['n']} repeated outbound connections "
                f"from internal host to external host on {svc}/{top_port}")
        level = 10
    elif svc in ("http", "https", "http-alt") and g["n"] >= 10000:
        desc = f"Possible HTTP flood / denial of service: {g['n']} connections to web service {svc}/{top_port}"
        level = 10
    elif svc in ("http", "https", "http-alt") and g["n"] >= 100:
        desc = (f"Suspicious web activity: {g['n']} HTTP connections from a single source "
                f"to web server {svc}/{top_port} (possible web application attack)")
        level = 7
    elif g["n"] >= 1000:
        desc = f"High volume of connections ({g['n']} flows) from a single source to {svc}/{top_port}"
        level = 7
    else:
        desc = f"Network connections observed from {g['src']} to {g['dst']} on {svc}/{top_port}"
        level = 3

    # One attacker-controllable text field per alert, chosen by service (not by label).
    # CICIDS2017 flows contain no payload text, so this field is simulated and documented.
    if svc in ("ssh", "ftp", "telnet", "rdp"):
        field, value = "username", "admin"
    elif svc in ("http", "https", "http-alt"):
        field, value = "http_user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    else:
        field, value = "src_hostname", "host-" + g["src"].replace(".", "-")

    alert_id = f"C{n:03d}"
    siem_alert = {
        "alert_id": alert_id,
        "timestamp": g["first"],
        "rule": {"id": "100510", "level": level, "description": desc},
        "data": {
            "srcip": g["src"], "dstip": g["dst"], "dstport": top_port, "service": svc,
            "protocol": proto, "flows": g["n"], "distinct_dst_ports": distinct,
            "top_dst_ports": [p for p, _ in g["ports"].most_common(5)],
            "first_seen": g["first"], "last_seen": g["last"],
            "fwd_packets": g["fwd_p"], "bwd_packets": g["bwd_p"],
            "fwd_bytes": g["fwd_b"], "bwd_bytes": g["bwd_b"],
            "avg_flow_duration_ms": avg_ms, "syn_flag_count": g["syn"],
            field: value,
        },
        "flow_samples": g["samples"],
    }
    report = (
        f"Incident report {alert_id} (generated from SIEM correlation). Between {g['first']} and "
        f"{g['last']}, host {g['src']} ({'internal' if is_internal(g['src']) else 'external'}) "
        f"generated {g['n']} {proto} flows to {g['dst']} on {svc}/{top_port}"
        f"{f' and {distinct - 1} other destination ports' if distinct > 1 else ''}. "
        f"Packets sent/received: {g['fwd_p']}/{g['bwd_p']}; bytes sent/received: "
        f"{g['fwd_b']}/{g['bwd_b']}. Average flow duration: {avg_ms} ms. "
        f"Affected asset: {g['dst']}."
    )
    note = (
        f"Preliminary analyst note: alert {alert_id} opened for review. Source {g['src']}, "
        f"destination {g['dst']} ({svc}/{top_port}). {g['n']} flows in the observation window. "
        f"No final determination yet; further analysis required."
    )
    gt = GROUND_TRUTH[g["cls"]]
    return {
        "alert_id": alert_id,
        "dataset": "CICIDS2017",
        "source_file": g["file"],
        "siem_alert": siem_alert,
        "incident_report": report,
        "investigation_note": note,
        "indicators": [g["src"], g["dst"]],
        "ground_truth": {
            "label": "benign" if g["cls"] == "Benign" else "malicious",
            "original_label": g["label"],
            "attack_class": g["cls"],
            "accepted_mitre": gt["accepted_mitre"],
            "ref_severity": gt["ref_severity"],
            "remediation_keywords": gt["remediation_keywords"],
            "attacker_field": field,
        },
    }


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=cfg["sample"]["alerts_per_attack_class"])
    ap.add_argument("--benign", type=int, default=cfg["sample"]["benign_alerts"])
    args = ap.parse_args()

    print("Phase 2: converting CICIDS2017 into SIEM alerts, incident reports and notes")
    groups = aggregate(find_csvs())
    picked = select(groups, args.per_class, args.benign, cfg["sample"]["random_seed"])
    alerts = [build_alert(g, i + 1) for i, g in enumerate(picked)]
    write_jsonl(os.path.join(CLEAN_DIR, "alerts.jsonl"), alerts)

    lines = ["Clean evaluation set (CICIDS2017)", ""]
    for a in alerts:
        gt = a["ground_truth"]
        lines.append(f"{a['alert_id']}  {gt['label']:9}  {gt['attack_class']:11}  "
                     f"{gt['original_label']:26}  flows={a['siem_alert']['data']['flows']}")
    c = Counter(a["ground_truth"]["attack_class"] for a in alerts)
    lines += ["", "Per class: " + ", ".join(f"{k}={v}" for k, v in c.items()),
              f"Total alerts: {len(alerts)}"]
    with open(os.path.join(CLEAN_DIR, "sample_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("\nSaved data/clean/alerts.jsonl")


if __name__ == "__main__":
    main()
