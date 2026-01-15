#!/usr/bin/env python3
# Save this as mitigation.py (overwrite existing)

import subprocess
import argparse
import chromadb
import re
import os
import sys
from typing import List, Tuple
import shlex

HIGH_CONF_THRESHOLD = 0.75
CHROMA_PATH = "/workspace/mitigation/chroma_db"
CHROMA_COLLECTION = "mitigation_plans"
PLAYBOOK_DIR = "/workspace/mitigation/playbooks"
GATEWAY_NAME = "api-gateway"
SANDBOX_GATEWAY_NAME = "sandbox-api-gateway"


# ----------------------------------------------
# Colors for terminal output
# ----------------------------------------------
class Color:
    Y = "\033[93m"
    G = "\033[92m"
    R = "\033[91m"
    B = "\033[94m"
    E = "\033[0m"


# ----------------------------------------------
# 1. ChromaDB Lookup
# ----------------------------------------------
def lookup_threat_from_chroma(threat_name: str):
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    print(Color.Y + "\n📚 Collections in ChromaDB:" + Color.E)
    collections = client.list_collections()
    print(collections)

    try:
        collection = client.get_collection(CHROMA_COLLECTION)
    except Exception as e:
        print(Color.R + f"❌ ERROR: {e}" + Color.E)
        sys.exit(1)

    result = collection.query(query_texts=[threat_name], n_results=1)

    if not result["documents"]:
        print(Color.R + "❌ No matching mitigation entry found in ChromaDB!" + Color.E)
        sys.exit(1)

    doc = result["documents"][0]
    # doc is usually a list with single string element
    entry_text = doc[0] if isinstance(doc, list) and len(doc) > 0 else doc
    print(Color.B + "\n📄 Retrieved KB Entry:\n" + Color.E + entry_text)
    return entry_text


# ----------------------------------------------
# 2. Parse the KB entry into fields (robust)
# ----------------------------------------------
def parse_kb_entry(text: str) -> Tuple[int, List[str], List[str]]:
    """
    Returns: tier (int), playbooks (list of filenames), vars_list (list of var names)
    Supports:
      - Playbook: foo.yml
      - Playbook-1: foo.yml
      - Playbook-2: bar.yml
      - Playbooks: foo.yml, bar.yml
    """
    if not isinstance(text, str):
        raise ValueError("KB entry is not a string")

    # Tier
    tier_match = re.search(r"Tier:\s*(\d+)", text, re.IGNORECASE)
    if not tier_match:
        raise ValueError("Tier not found in KB entry")
    tier = int(tier_match.group(1))

    # Playbooks: multiple syntaxes
    playbooks = re.findall(r"Playbook(?:[-\w\d]*)\s*:\s*([\w\-.]+)", text, re.IGNORECASE)
    if not playbooks:
        # try Playbooks: comma separated
        m = re.search(r"Playbooks:\s*([A-Za-z0-9_\-,.\s]+)", text, re.IGNORECASE)
        if m:
            raw = m.group(1)
            playbooks = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
    if not playbooks:
        raise ValueError("No Playbook lines found in KB entry")

    # Required_Vars
    vars_match = re.search(r"Required_Vars:\s*([^\n]+)", text, re.IGNORECASE)
    if not vars_match:
        raise ValueError("Required_Vars not found in KB entry")
    vars_list = [v.strip() for v in vars_match.group(1).split(",") if v.strip()]

    return tier, playbooks, vars_list


# ----------------------------------------------
# 3. Build var dict based on Required_Vars
# ----------------------------------------------
def build_vars_dict(vars_list, ip, target):
    vars_dict = {}
    for v in vars_list:
        # normalize common possible var names
        if v == "source_ip":
            vars_dict[v] = ip
        elif v in ("target_container", "target_container_name"):
            # accept either name from KB and set both keys later via normalization
            vars_dict[v] = target
        elif v == "threat_name":
            # threat_name is optional for playbooks
            vars_dict[v] = ""  # leave blank unless playbooks require it
        else:
            # keep unknown vars as empty string but warn
            print(Color.Y + f"⚠ Unknown var '{v}', leaving blank." + Color.E)
            vars_dict[v] = ""
    return vars_dict


# ----------------------------------------------
# normalize variable names so playbooks with either name accept them
# ----------------------------------------------
def normalize_vars(vars_dict):
    # ensure both 'target_container' and 'target_container_name' exist if either exists
    td = vars_dict.copy()
    if "target_container_name" in td and "target_container" not in td:
        td["target_container"] = td["target_container_name"]
    if "target_container" in td and "target_container_name" not in td:
        td["target_container_name"] = td["target_container"]
    return td


# ----------------------------------------------
# 4. Run Ansible Playbook
# ----------------------------------------------
def run_playbook(playbook, vars_dict, check=False) -> bool:
    playbook_path = os.path.join(PLAYBOOK_DIR, playbook)
    if not os.path.exists(playbook_path):
        print(Color.R + f"❌ Playbook not found: {playbook_path}" + Color.E)
        return False

    cmd = ["ansible-playbook", playbook_path]

    for k, v in vars_dict.items():
        # Quote values safely
        cmd.extend(["-e", f"{k}={shlex.quote(str(v))}"])

    if check:
        cmd.append("--check")

    print(Color.B + f"\n▶ Running: {' '.join(cmd)}" + Color.E)
    result = subprocess.run(cmd, capture_output=True, text=True)

    # print outputs for debugging
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)

    return result.returncode == 0


# ----------------------------------------------
# Helper: Try to find a Tier-2 alternative for low-confidence Tier-1
# ----------------------------------------------
def try_find_tier2_alternative(threat_name: str) -> Tuple[int, List[str], List[str]]:
    """
    Best-effort: query Chroma for "<threat_name> tier 2" and parse entry if found.
    Returns parsed entry or raises ValueError.
    """
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_collection(CHROMA_COLLECTION)
    alt_query = f"{threat_name} tier 2"
    result = collection.query(query_texts=[alt_query], n_results=1)
    if not result["documents"]:
        raise ValueError("No alternative Tier-2 entry found")
    doc = result["documents"][0]
    entry_text = doc[0] if isinstance(doc, list) and len(doc) > 0 else doc
    return parse_kb_entry(entry_text)


# ----------------------------------------------
# Execute multiple playbooks in order (with dry-run option)
# ----------------------------------------------
def execute_playbooks(playbooks: List[str], vars_dict: dict, check=False) -> bool:
    for pb in playbooks:
        ok = run_playbook(pb, vars_dict, check=check)
        if not ok:
            print(Color.R + f"❌ Playbook failed: {pb}" + Color.E)
            return False
    return True


# ----------------------------------------------
# 5. Main Mitigation Flow
# ----------------------------------------------
def mitigate(threat, ip, target, confidence):
    print(Color.B + "\n==============================")
    print("🔥 MITIGATION PIPELINE START")
    print("==============================\n" + Color.E)

    # 1. Query knowledge base
    kb_text = lookup_threat_from_chroma(threat)
    try:
        tier, playbooks, vars_list = parse_kb_entry(kb_text)
    except Exception as e:
        print(Color.R + f"❌ Failed to parse KB entry: {e}" + Color.E)
        sys.exit(1)

    print(Color.G + f"\n📌 Tier from KB: {tier}" + Color.E)
    print(Color.G + f"📌 Playbooks: {playbooks}" + Color.E)
    print(Color.G + f"📌 Required Vars: {vars_list}\n" + Color.E)

    # 2. Confidence override: if Tier1 but low confidence, try to find a Tier2 alternative
    if confidence < HIGH_CONF_THRESHOLD and tier == 1:
        print(Color.Y + f"⚠ Low confidence ({confidence}) and KB says Tier 1. Trying to find a Tier-2 alternative..." + Color.E)
        try:
            tier2_t, tier2_playbooks, tier2_vars = try_find_tier2_alternative(threat)
            print(Color.G + f"✔ Found Tier-2 alternative: playbooks={tier2_playbooks}" + Color.E)
            tier, playbooks, vars_list = tier2_t, tier2_playbooks, tier2_vars
        except Exception:
            print(Color.Y + "⚠ No explicit Tier-2 alternative found — continuing with KB playbooks but sandbox-first." + Color.E)
            # fall back to original playbooks

    # 3. If playbook seems to be nginx block, override target to gateway (prevents user mistakes)
    is_gateway_playbook = any("nginx" in pb.lower() or "gateway" in pb.lower() for pb in playbooks)
    if is_gateway_playbook:
        if target != GATEWAY_NAME:
            print(Color.Y + f"⚠ KB mitigation targets the API Gateway. Overriding target '{target}' -> '{GATEWAY_NAME}'." + Color.E)
        target = GATEWAY_NAME

    # 4. Build dictionaries for production + sandbox
    prod_vars = build_vars_dict(vars_list, ip, target)
    # normalize so both naming conventions exist
    prod_vars = normalize_vars(prod_vars)
    sandbox_vars = prod_vars.copy()

    # For sandbox: if it's an API gateway playbook, point to SANDBOX_GATEWAY_NAME
    if is_gateway_playbook:
        sandbox_vars["target_container"] = SANDBOX_GATEWAY_NAME
        sandbox_vars["target_container_name"] = SANDBOX_GATEWAY_NAME
    else:
        # if a target exists, create a sandboxed variant by prefixing 'sandbox-' if not already sandbox
        if "target_container" in prod_vars and prod_vars["target_container"]:
            if not prod_vars["target_container"].startswith("sandbox-"):
                sandbox_vars["target_container"] = f"sandbox-{prod_vars['target_container']}"
            else:
                sandbox_vars["target_container"] = prod_vars["target_container"]
            sandbox_vars["target_container_name"] = sandbox_vars["target_container_name"] if sandbox_vars.get("target_container_name") else sandbox_vars["target_container"]
        elif "target_container_name" in prod_vars and prod_vars["target_container_name"]:
            if not prod_vars["target_container_name"].startswith("sandbox-"):
                sandbox_vars["target_container_name"] = f"sandbox-{prod_vars['target_container_name']}"
            else:
                sandbox_vars["target_container_name"] = prod_vars["target_container_name"]
            sandbox_vars["target_container"] = sandbox_vars.get("target_container", sandbox_vars["target_container_name"])

    # ---------------------------
    # SANDBOX PHASE
    # ---------------------------
    print(Color.B + "\n🧪 SANDBOX STAGE\n" + Color.E)

    print(Color.Y + "➡ Step 1: Dry-run (--check)" + Color.E)
    if not execute_playbooks(playbooks, sandbox_vars, check=True):
        print(Color.R + "❌ Sandbox dry-run failed. Aborting." + Color.E)
        return

    print(Color.Y + "\n➡ Step 2: Sandbox execution" + Color.E)
    if not execute_playbooks(playbooks, sandbox_vars, check=False):
        print(Color.R + "❌ Sandbox execution failed. Aborting." + Color.E)
        return

    # Ask user before real execution
    proceed = input(Color.Y + "\n⚠ Sandbox succeeded. Proceed with REAL mitigation? (yes/no): " + Color.E)
    if proceed.lower() != "yes":
        print(Color.R + "❌ Real mitigation cancelled by user." + Color.E)
        return

    # ---------------------------
    # PRODUCTION PHASE
    # ---------------------------
    print(Color.G + "\n🚀 PRODUCTION STAGE\n" + Color.E)
    # ensure prod_vars normalized again before running
    prod_vars = normalize_vars(prod_vars)
    if execute_playbooks(playbooks, prod_vars, check=False):
        print(Color.G + "✅ REAL mitigation executed successfully!" + Color.E)
    else:
        print(Color.R + "❌ Real mitigation failed." + Color.E)


# ----------------------------------------------
# CLI ENTRY
# ----------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threat", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--confidence", type=float, required=True)
    args = parser.parse_args()

    mitigate(args.threat, args.ip, args.target, args.confidence)
