"""
Run the whole pipeline in order.

    python run_all.py                 # convert -> inject -> wazuh -> triage -> evaluate
    python run_all.py --skip-wazuh    # same, without sending alerts through Wazuh
    python run_all.py --only evaluate # one step: convert | inject | wazuh | triage | evaluate
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STEPS = [("convert", "converter.py"), ("inject", "inject.py"), ("wazuh", "wazuh_ingest.py"),
         ("triage", "triage.py"), ("evaluate", "evaluate.py")]


def run(script, extra):
    print("\n" + "=" * 70 + f"\n>>> {script}\n" + "=" * 70, flush=True)
    r = subprocess.run([sys.executable, os.path.join(HERE, "src", script)] + extra)
    if r.returncode != 0:
        print(f"\nStopped: {script} failed. Fix the problem and run again "
              f"(finished AI runs are kept).")
        sys.exit(r.returncode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=[s for s, _ in STEPS])
    ap.add_argument("--skip-wazuh", action="store_true")
    args, extra = ap.parse_known_args()       # anything else (e.g. --limit 2) goes to triage.py
    for name, script in STEPS:
        if args.only and name != args.only:
            continue
        if name == "wazuh" and args.skip_wazuh:
            continue
        run(script, extra if name == "triage" else [])


if __name__ == "__main__":
    main()
