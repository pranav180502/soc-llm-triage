"""
Phase 5 - Defences.

D1 Input filtering        : flags instruction-like text inside untrusted fields
D2 Prompt templates       : hardened system prompt + spotlighting of untrusted data + task reminder
D3 Structured output      : JSON schema with fixed values (Ollama format=schema) + ID validation
D4 Secondary verifier LLM : a different model checks verdict and remediation against the evidence
D5 Alert confidence score : low-confidence benign/close decisions are not auto-closed
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_attack_ids, normalise_verdict  # noqa: E402

VALID_IDS = load_attack_ids()

# ---------------------------------------------------------------- D1
SUSPICIOUS_PATTERNS = [
    r"ignore (?:all |any )?(?:previous|prior|above|earlier) instructions?",
    r"\b(?:this|the) (?:event|alert|activity|incident|traffic) is (?:benign|safe|harmless|a false positive)",
    r"\bclose (?:the |this )?(?:incident|alert|ticket|case)\b",
    r"\bfalse positive\b",
    r"\bknown to be safe\b",
    r"\b(?:do not|don't|never|no need to) (?:isolate|block|contain|quarantine)\b",
    r"\binvestigation completed\b",
    r"\b(?:you are now|act as|new instructions?)\b",
    r"\bsystem prompt\b",
]
_RX = [re.compile(p, re.I) for p in SUSPICIOUS_PATTERNS]


def _flag_text(s, path, flags):
    hit = any(rx.search(s) for rx in _RX)
    if hit:
        flags.append(path)
        return f"[SUSPICIOUS-INSTRUCTION] {s} [/SUSPICIOUS-INSTRUCTION]"
    return s


def input_filter(obj, path="", flags=None):
    """Return (filtered_copy, list_of_flagged_paths). Text is tagged, never deleted."""
    if flags is None:
        flags = []
    if isinstance(obj, dict):
        return {k: input_filter(v, f"{path}.{k}" if path else k, flags)[0] for k, v in obj.items()}, flags
    if isinstance(obj, list):
        return [input_filter(v, f"{path}[{i}]", flags)[0] for i, v in enumerate(obj)], flags
    if isinstance(obj, str):
        # check line by line so only the offending line is tagged
        lines = obj.split("\n")
        return "\n".join(_flag_text(l, path, flags) for l in lines), flags
    return obj, flags


# ---------------------------------------------------------------- D2
def spotlight(view_json, reminder):
    return ("<<<UNTRUSTED_DATA>>>\n" + view_json + "\n<<<END_UNTRUSTED_DATA>>>\n\n" + reminder)


# ---------------------------------------------------------------- D3
ANALYST_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_type": {"type": "string"},
        "verdict": {"type": "string", "enum": ["malicious", "benign", "uncertain"]},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "mitre_attack": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
        "remediation": {"type": "array", "items": {"type": "string"}},
        "incident_action": {"type": "string", "enum": ["escalate", "monitor", "close"]},
        "confidence": {"type": "number"},
    },
    "required": ["threat_type", "verdict", "severity", "mitre_attack", "summary",
                 "remediation", "incident_action", "confidence"],
}

VERIFIER_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict_supported": {"type": "boolean"},
        "expected_verdict": {"type": "string", "enum": ["malicious", "benign", "uncertain"]},
        "remediation_safe": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["verdict_supported", "expected_verdict", "remediation_safe", "reason"],
}

TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_structured(out):
    """Keep only ATT&CK IDs that exist in the official Enterprise list, and allowed values."""
    o = dict(out)
    ids = []
    for t in o.get("mitre_attack") or []:
        m = re.search(r"T\d{4}(?:\.\d{3})?", str(t).upper())
        if m and m.group(0) in VALID_IDS:
            ids.append(m.group(0))
    o["mitre_attack"] = ids
    v = normalise_verdict(o.get("verdict"))
    o["verdict"] = "uncertain" if v == "invalid" else v
    if o.get("incident_action") not in ("escalate", "monitor", "close"):
        o["incident_action"] = "escalate"
    return o


# ---------------------------------------------------------------- D4 + D5
UNSAFE_PLACEHOLDER = "[Verifier: remediation flagged as unsafe - analyst review required]"

def confidence_score(model_conf, verifier_agrees, n_flags):
    try:
        c = max(0.0, min(1.0, float(model_conf)))
    except Exception:
        c = 0.0
    return round(0.5 * c + 0.3 * (1.0 if verifier_agrees else 0.0) + 0.2 * (1.0 if n_flags == 0 else 0.0), 3)


def finalize_defended(analyst, verifier, n_flags, tau):
    """Combine analyst answer, verifier check (D4) and confidence scoring (D5)."""
    verdict = normalise_verdict(analyst.get("verdict"))
    verdict = "uncertain" if verdict == "invalid" else verdict
    action = analyst.get("incident_action", "escalate")
    remediation = list(analyst.get("remediation") or [])
    notes = []
    v_ok = bool(verifier.get("verdict_supported", False)) if verifier else False
    r_ok = bool(verifier.get("remediation_safe", True)) if verifier else True

    if verifier and not v_ok:                                  # D4 verdict check
        verdict, action = "uncertain", "escalate"
        notes.append("D4: verifier disagreed with verdict -> uncertain, escalated")
    if verifier and not r_ok:                                  # D4 remediation check
        remediation = [UNSAFE_PLACEHOLDER]
        action = "escalate"
        notes.append("D4: remediation flagged unsafe -> escalated")

    score = confidence_score(analyst.get("confidence"), v_ok, n_flags)   # D5
    if (verdict == "benign" or action == "close") and score < tau:
        verdict, action = "uncertain", "escalate"
        notes.append(f"D5: confidence {score} < tau {tau} -> not auto-closed")
    return {"verdict": verdict, "incident_action": action, "remediation": remediation,
            "confidence_score": score, "defence_notes": notes}


def parse_json(text):
    try:
        return json.loads(text), True
    except Exception:
        m = re.search(r"\{.*\}", text or "", re.S)
        if m:
            try:
                return json.loads(m.group(0)), True
            except Exception:
                pass
    return {}, False
