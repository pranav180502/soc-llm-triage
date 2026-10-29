"""
SOC layer - send the converted alerts (clean + A1-poisoned) through the Wazuh SIEM.

What it does (all through the docker CLI, nothing to edit by hand):
  1. adds a <localfile> entry (log_format json) to the Wazuh manager's ossec.conf,
  2. adds custom rules 100510-100513 to local_rules.xml,
  3. restarts the Wazuh manager,
  4. appends one JSON event per alert to the monitored file,
  5. reads back the alerts Wazuh generated from /var/ossec/logs/alerts/alerts.json,
  6. checks whether the prompt-injection payload (A1) survived SIEM processing.

Only A1 is a log-borne attack; A2-A4 live outside the SIEM (case notes, threat intel,
playbooks) and are added by triage.py.

Requires: Docker Desktop running and Wazuh started (docker compose start).
Output: data/wazuh/wazuh_alerts.jsonl and data/wazuh/ingest_report.txt
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import CLEAN_DIR, POISON_DIR, WAZUH_DIR, load_config, read_jsonl, write_jsonl  # noqa: E402

LOCALFILE_BLOCK = """
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>{path}</location>
  </localfile>
</ossec_config>
"""

RULES = """
<group name="llm_triage,">
  <rule id="100510" level="3">
    <decoded_as>json</decoded_as>
    <field name="soc_project">^llm-triage$</field>
    <description>Flow correlation: $(alert_description)</description>
  </rule>
  <rule id="100511" level="7">
    <if_sid>100510</if_sid>
    <field name="rule_level">^7$</field>
    <description>Flow correlation: $(alert_description)</description>
  </rule>
  <rule id="100512" level="8">
    <if_sid>100510</if_sid>
    <field name="rule_level">^8$</field>
    <description>Flow correlation: $(alert_description)</description>
  </rule>
  <rule id="100513" level="10">
    <if_sid>100510</if_sid>
    <field name="rule_level">^10$</field>
    <description>Flow correlation: $(alert_description)</description>
  </rule>
</group>
"""

HIDDEN_KEYS = {"soc_project", "pipeline_id", "condition", "ingest_run", "rule_level", "alert_description"}


def docker(container, *args, input_text=None, check=True):
    cmd = ["docker", "exec", "-i", container] + list(args)
    # bytes, not text: avoids Windows turning \n into \r\n inside the container files
    data = input_text.encode("utf-8") if input_text is not None else None
    try:
        r = subprocess.run(cmd, input=data, capture_output=True)
    except FileNotFoundError:
        print("The 'docker' command was not found. Is Docker Desktop installed and open?")
        sys.exit(1)
    out = r.stdout.decode("utf-8", "replace")
    if check and r.returncode != 0:
        print("Docker command failed:", " ".join(cmd[:5]), "...")
        print(r.stderr.decode("utf-8", "replace").strip() or out.strip())
        print("Is Docker Desktop open and Wazuh started?  (docker compose start)")
        sys.exit(1)
    return out


def event_from_package(pkg, run_tag):
    a = pkg["siem_alert"]
    ev = {"soc_project": "llm-triage", "pipeline_id": f"{pkg['alert_id']}-{pkg['condition']}",
          "condition": pkg["condition"], "ingest_run": run_tag, "alert_id": pkg["alert_id"],
          "rule_level": str(a["rule"]["level"]), "alert_description": a["rule"]["description"],
          "event_time": a["timestamp"]}
    ev.update(a["data"])
    ev["flow_samples"] = " | ".join(a.get("flow_samples", []))
    return ev


def main():
    cfg = load_config()
    c = cfg["wazuh"]["manager_container"]
    path = cfg["wazuh"]["events_path_in_container"]
    packages = read_jsonl(os.path.join(CLEAN_DIR, "packages.jsonl"))
    a1 = read_jsonl(os.path.join(POISON_DIR, "A1.jsonl"))
    if not packages:
        print("Run converter.py and inject.py first.")
        sys.exit(1)

    print("1/5 Checking Wazuh manager container ...")
    docker(c, "true")

    print("2/5 Configuring Wazuh (localfile + custom rules) ...")
    conf = docker(c, "cat", "/var/ossec/etc/ossec.conf")
    if path not in conf:
        docker(c, "sh", "-c", "cat >> /var/ossec/etc/ossec.conf",
               input_text=LOCALFILE_BLOCK.format(path=path))
    rules = docker(c, "cat", "/var/ossec/etc/rules/local_rules.xml")
    if "llm-triage" not in rules:
        docker(c, "sh", "-c", "cat >> /var/ossec/etc/rules/local_rules.xml", input_text=RULES)
    docker(c, "sh", "-c", f"touch {path} && chmod 644 {path}")

    print("3/5 Restarting Wazuh manager (about 30-60 s) ...")
    docker(c, "/var/ossec/bin/wazuh-control", "restart", check=False)
    for _ in range(24):                                   # wait until log collection is up
        time.sleep(5)
        st = docker(c, "/var/ossec/bin/wazuh-control", "status", check=False)
        if "wazuh-logcollector is running" in st and "wazuh-analysisd is running" in st:
            break
    time.sleep(10)                                        # let logcollector open the file

    run_tag = time.strftime("%Y%m%d-%H%M%S")
    events = [event_from_package(p, run_tag) for p in packages + a1]
    print(f"4/5 Sending {len(events)} events to Wazuh ...")
    docker(c, "sh", "-c", f"cat >> {path}",
           input_text="".join(json.dumps(e) + "\n" for e in events))

    print("5/5 Waiting for Wazuh to generate alerts ...")
    wanted = {e["pipeline_id"] for e in events}
    found = {}
    for attempt in range(24):                             # up to ~2 min
        time.sleep(5)
        if attempt == 12 and len(found) < len(wanted):   # resend anything not yet seen once
            missing = [e for e in events if e["pipeline_id"] not in found]
            print(f"   resending {len(missing)} events not seen yet ...")
            docker(c, "sh", "-c", f"cat >> {path}",
                   input_text="".join(json.dumps(e) + "\n" for e in missing))
        out = docker(c, "sh", "-c",
                     f"grep '{run_tag}' /var/ossec/logs/alerts/alerts.json || true")
        for line in out.splitlines():
            try:
                al = json.loads(line)
            except Exception:
                continue
            d = al.get("data", {})
            pid = d.get("pipeline_id")
            if pid in wanted:
                found[pid] = al
        print(f"   alerts received: {len(found)}/{len(wanted)}")
        if len(found) == len(wanted):
            break

    rows = []
    for pid, al in found.items():
        d = al.get("data", {})
        rows.append({
            "pipeline_id": pid, "alert_id": d.get("alert_id"), "condition": d.get("condition"),
            "wazuh_alert": {
                "timestamp": al.get("timestamp"),
                "rule": {k: al.get("rule", {}).get(k) for k in ("id", "level", "description")},
                "agent": al.get("agent", {}).get("name"),
                "location": al.get("location"),
                "data": {k: v for k, v in d.items() if k not in HIDDEN_KEYS},
            },
        })
    write_jsonl(os.path.join(WAZUH_DIR, "wazuh_alerts.jsonl"), rows)

    # Did the A1 payload survive the SIEM unchanged?
    survived, checked = 0, 0
    by_pid = {r["pipeline_id"]: r for r in rows}
    for p in a1:
        r = by_pid.get(f"{p['alert_id']}-A1")
        if not r:
            continue
        checked += 1
        field = p["ground_truth"]["attacker_field"]
        if r["wazuh_alert"]["data"].get(field) == p["siem_alert"]["data"][field]:
            survived += 1
    report = [
        f"Wazuh ingestion run {run_tag}",
        f"Events sent: {len(events)}  (clean: {len(packages)}, A1-poisoned: {len(a1)})",
        f"Alerts generated by Wazuh: {len(found)}",
        f"A1 payload passed through Wazuh unchanged: {survived}/{checked}",
    ]
    if len(found) < len(wanted):
        report.append("Missing: " + ", ".join(sorted(wanted - set(found))))
    with open(os.path.join(WAZUH_DIR, "ingest_report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")
    print("\n".join(report))
    print("Saved data/wazuh/wazuh_alerts.jsonl")
    print("Wazuh dashboard: https://localhost -> Threat Hunting -> search:  rule.groups:llm_triage")


if __name__ == "__main__":
    main()
