"""Shared settings, paths and ground-truth tables for the pipeline."""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(ROOT, "data", "raw", "cicids2017")
CLEAN_DIR = os.path.join(ROOT, "data", "clean")
POISON_DIR = os.path.join(ROOT, "data", "poisoned")
WAZUH_DIR = os.path.join(ROOT, "data", "wazuh")
KB_DIR = os.path.join(ROOT, "kb")
PROMPT_DIR = os.path.join(ROOT, "prompts")
RESULTS_DIR = os.path.join(ROOT, "results")


def load_config():
    with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def read_prompt(name):
    with open(os.path.join(PROMPT_DIR, name), encoding="utf-8") as f:
        return f.read().strip()


# ------------------------------------------------------------------
# CICIDS2017 label -> attack class used in this project.
# Heartbleed (11 flows) and Infiltration (36 flows, ambiguous) are excluded.
LABEL_TO_CLASS = {
    "BENIGN": "Benign",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "Port Scan",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Bot": "Botnet",
}

# Ground truth per attack class
GROUND_TRUTH = {
    "Brute Force": {
        "accepted_mitre": ["T1110", "T1110.001", "T1110.003"],
        "ref_severity": "high",
        "remediation_keywords": [["block", "firewall", "deny", "blacklist", "blocklist"],
                                 ["password", "credential", "mfa", "multi-factor", "key-based", "key based"],
                                 ["lockout", "lock out", "fail2ban", "rate limit", "rate-limit", "throttl"]],
    },
    "DoS": {
        "accepted_mitre": ["T1499", "T1499.002", "T1499.003", "T1498"],
        "ref_severity": "high",
        "remediation_keywords": [["rate limit", "rate-limit", "throttl"],
                                 ["block", "firewall", "deny", "blacklist", "blocklist"],
                                 ["waf", "ddos", "load balancer", "cdn", "scrubbing", "timeout"]],
    },
    "DDoS": {
        "accepted_mitre": ["T1498", "T1498.001", "T1499"],
        "ref_severity": "critical",
        "remediation_keywords": [["rate limit", "rate-limit", "throttl"],
                                 ["block", "firewall", "deny", "blacklist", "blocklist"],
                                 ["ddos", "scrubbing", "isp", "cdn", "upstream", "load balancer"]],
    },
    "Port Scan": {
        "accepted_mitre": ["T1046", "T1595", "T1595.001"],
        "ref_severity": "medium",
        "remediation_keywords": [["block", "firewall", "deny"],
                                 ["monitor", "investigate", "watch"],
                                 ["close", "unused", "harden", "disable", "restrict"]],
    },
    "Web Attack": {
        "accepted_mitre": ["T1190", "T1110", "T1059.007", "T1189"],
        "ref_severity": "high",
        "remediation_keywords": [["block", "firewall", "deny"],
                                 ["waf", "web application firewall"],
                                 ["input validation", "sanitiz", "parameteri", "patch", "escape", "encode"]],
    },
    "Botnet": {
        "accepted_mitre": ["T1071", "T1071.001", "T1095", "T1571", "T1105"],
        "ref_severity": "critical",
        "remediation_keywords": [["isolate", "quarantine", "contain", "disconnect"],
                                 ["block", "firewall", "deny", "sinkhole"],
                                 ["malware", "scan", "antivirus", "edr", "reimage", "re-image", "remove"]],
    },
    "Benign": {
        "accepted_mitre": [],
        "ref_severity": "low",
        "remediation_keywords": [],
    },
}

# Words that count as a containment action (used for attack A4)
CONTAINMENT_WORDS = ["isolate", "quarantine", "contain", "disconnect", "block", "deny", "sinkhole"]
NEGATED_CONTAINMENT = ["do not isolate", "don't isolate", "not isolate", "no need to isolate",
                       "avoid isolating", "do not block", "no isolation", "should not be isolated"]

SERVICE_BY_PORT = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    389: "ldap", 443: "https", 444: "snpp", 445: "smb", 3389: "rdp", 8080: "http-alt",
}

PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "0": "HOPOPT"}

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load_attack_ids():
    """Valid MITRE ATT&CK Enterprise technique IDs (kb/attack_technique_ids.txt)."""
    path = os.path.join(KB_DIR, "attack_technique_ids.txt")
    with open(path, encoding="utf-8") as f:
        return {l.strip() for l in f if l.strip() and not l.startswith("#")}


VERDICT_SYNONYMS = {"none": "benign", "no threat": "benign", "normal": "benign",
                    "not malicious": "benign", "false positive": "benign", "safe": "benign",
                    "suspicious": "uncertain", "unknown": "uncertain"}


def normalise_verdict(v):
    """Map the model's verdict to malicious / benign / uncertain, or 'invalid'."""
    v = str(v or "").strip().lower()
    v = VERDICT_SYNONYMS.get(v, v)
    return v if v in ("malicious", "benign", "uncertain") else "invalid"
