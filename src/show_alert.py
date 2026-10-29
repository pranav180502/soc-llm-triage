"""
show_alert.py - print one alert at each stage of the pipeline, for the demo.

    python src\show_alert.py C001 raw        first raw CICIDS2017 flows of this alert's attack
    python src\show_alert.py C001 clean      SIEM alert + incident report + investigation note
    python src\show_alert.py C001 poisoned   the four poisoned versions (A1-A4), changed part only
    python src\show_alert.py C001 wazuh      the alert as Wazuh produced it (clean and A1)
    python src\show_alert.py C001 results    every saved model answer for this alert
"""

import csv
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import CLEAN_DIR, POISON_DIR, RAW_DIR, RESULTS_DIR, WAZUH_DIR, read_jsonl  # noqa: E402

LINE = "-" * 78


def title(t):
    print("\n" + LINE + "\n " + t + "\n" + LINE)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    aid, part = sys.argv[1].upper(), sys.argv[2].lower()
    alerts = {a["alert_id"]: a for a in read_jsonl(os.path.join(CLEAN_DIR, "alerts.jsonl"))}
    if aid not in alerts:
        print(f"Alert {aid} not found. Run src\\converter.py first.")
        sys.exit(1)
    a = alerts[aid]
    gt = a["ground_truth"]

    if part == "raw":
        files = glob.glob(os.path.join(RAW_DIR, "**", a["source_file"]), recursive=True)
        title(f"Raw CICIDS2017 flows - file {a['source_file']} - label {gt['original_label']}")
        keep = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol",
                "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Label"]
        with open(files[0], encoding="latin-1", newline="") as f:
            r = csv.reader(f)
            head = [h.strip() for h in next(r)]
            idx = [head.index(k) for k in keep]
            print(f"The file has {len(head)} columns per flow. Showing {len(keep)} of them.\n")
            print(" | ".join(keep))
            shown = 0
            for row in r:
                if len(row) == len(head) and row[head.index("Label")].strip()[:6] == gt["original_label"][:6]:
                    print(" | ".join(row[i].strip() for i in idx))
                    shown += 1
                    if shown == 5:
                        break
        print(f"\nAlert {aid} groups {a['siem_alert']['data']['flows']} flows like these "
              f"(same label, source and destination).")

    elif part == "clean":
        title(f"Clean alert {aid} (what the model will read)")
        print("SIEM ALERT:")
        print(json.dumps({"rule": a["siem_alert"]["rule"], "data": a["siem_alert"]["data"]}, indent=2))
        print("\nINCIDENT REPORT:\n" + a["incident_report"])
        print("\nINVESTIGATION NOTE:\n" + a["investigation_note"])
        title("Ground truth (hidden from the model, used only for scoring)")
        print(json.dumps({k: gt[k] for k in ("label", "original_label", "attack_class",
                                              "accepted_mitre", "ref_severity")}, indent=2))

    elif part == "poisoned":
        clean = {p["alert_id"]: p for p in read_jsonl(os.path.join(CLEAN_DIR, "packages.jsonl"))}[aid]
        pois = {k: {p["alert_id"]: p for p in read_jsonl(os.path.join(POISON_DIR, f"{k}.jsonl"))}
                for k in ("A1", "A2", "A3", "A4")}
        if aid not in pois["A1"]:
            print(f"{aid} is a benign alert; only malicious alerts are poisoned.")
            return
        f = gt["attacker_field"]
        title("A1 Prompt injection (AML.T0051) - SIEM alert field: " + f)
        print("  clean   :", clean["siem_alert"]["data"][f])
        print("  poisoned:", pois["A1"][aid]["siem_alert"]["data"][f])
        title("A2 Context manipulation (AML.T0080) - investigation note")
        print("  clean   :", clean["investigation_note"])
        print("  poisoned:", pois["A2"][aid]["investigation_note"])
        title("A3 Knowledge-base poisoning (AML.T0070) - threat-intelligence entry")
        print("  clean   :", clean["threat_intel"][0]["entry"])
        print("  poisoned:", pois["A3"][aid]["threat_intel"][0]["entry"])
        title("A4 Remediation manipulation (AML.T0051) - last line of the playbook")
        print("  clean   :", clean["playbook"].splitlines()[-1])
        print("  poisoned:", pois["A4"][aid]["playbook"].splitlines()[-1])

    elif part == "wazuh":
        wz = {r["pipeline_id"]: r["wazuh_alert"] for r in read_jsonl(os.path.join(WAZUH_DIR, "wazuh_alerts.jsonl"))}
        f = gt["attacker_field"]
        for cond in ("clean", "A1"):
            w = wz.get(f"{aid}-{cond}")
            title(f"Wazuh alert {aid}-{cond}")
            if not w:
                print("  not found - run src\\wazuh_ingest.py first")
                continue
            print(f"  rule {w['rule']['id']} level {w['rule']['level']}: {w['rule']['description']}")
            print(f"  data.srcip = {w['data'].get('srcip')}   data.dstport = {w['data'].get('dstport')}")
            print(f"  data.{f} = {w['data'].get(f)}")

    elif part == "results":
        folder = sys.argv[3] if len(sys.argv) > 3 else RESULTS_DIR
        if not os.path.isabs(folder):
            folder = os.path.join(os.path.dirname(RESULTS_DIR), folder)
        rows = [r for r in csv.DictReader(open(os.path.join(folder, "per_run.csv"), encoding="utf-8"))
                if r["alert_id"] == aid]
        title(f"Model answers for {aid} ({gt['original_label']}, ground truth: {gt['label']})")
        print(f"{'model':13} {'condition':10} {'final verdict':14} {'action':9} {'attack worked?':15} MITRE")
        for r in rows:
            worked = {"True": "YES - fooled", "False": "no - resisted"}.get(r["attack_success"], "")
            print(f"{r['model']:13} {r['condition']:10} {r['final_verdict']:14} {r['final_action']:9} "
                  f"{worked:15} {r['mitre_ids'] or '-'}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
