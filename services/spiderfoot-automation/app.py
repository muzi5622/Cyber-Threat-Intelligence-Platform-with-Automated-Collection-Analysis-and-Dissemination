
import os
import re
import json
import time
import hashlib
import subprocess
from urllib.parse import urlparse
import requests

# -------------------------
# Config
# -------------------------
OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "600"))
REPORT_LIMIT = int(os.getenv("REPORT_LIMIT", "30"))

SF_TIMEOUT_SECONDS = int(os.getenv("SF_TIMEOUT_SECONDS", "300"))
SF_USECASE = os.getenv("SF_USECASE", "passive")
SF_MODULES = os.getenv("SF_MODULES", "")
SF_MAX_THREADS = int(os.getenv("SF_MAX_THREADS", "10"))
SF_MAX_TARGETS_PER_CYCLE = int(os.getenv("SF_MAX_TARGETS_PER_CYCLE", "3"))

STATE_PATH = os.getenv("STATE_PATH", "/data/state.json")
OUT_DIR = os.getenv("OUT_DIR", "/data/scans")

GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}

LABEL_VALUE = "spiderfoot-enriched"

RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RX_DOMAIN = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RX_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# -------------------------
# Helpers
# -------------------------
def log(msg):
    print(f"[spiderfoot-automation] {msg}", flush=True)

def gql(query, variables=None):
    r = requests.post(GQL, headers=HEADERS, json={"query": query, "variables": variables or {}}, timeout=60)
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

def load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"seen_reports": [], "seen_targets": []}

def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)

def ensure_label():
    q_find = """
    query FindLabel($search: String!) {
      labels(search: $search, first: 1) {
        edges { node { id value } }
      }
    }
    """
    d = gql(q_find, {"search": LABEL_VALUE})
    edges = d["labels"]["edges"]
    if edges:
        return edges[0]["node"]["id"]

    q_create = """
    mutation CreateLabel($input: LabelAddInput!) {
      labelAdd(input: $input) { id value }
    }
    """
    d = gql(q_create, {"input": {"value": LABEL_VALUE, "color": "#03a9f4"}})
    return d["labelAdd"]["id"]

def fetch_recent_reports(limit=20):
    q = """
    query Reports($first: Int!) {
      reports(first: $first, orderBy: created_at, orderMode: desc) {
        edges {
          node {
            id
            name
            description
            created_at
          }
        }
      }
    }
    """
    d = gql(q, {"first": limit})
    return [e["node"] for e in d["reports"]["edges"]]

# -------- URL → DOMAIN (core fix) --------
def url_to_domain(u):
    try:
        u = (u or "").strip()
        if not u:
            return None
        if "://" not in u:
            u = "http://" + u
        p = urlparse(u)
        host = (p.hostname or "").strip().lower()
        if not host:
            return None
        if host in ("localhost",):
            return None
        return host
    except Exception:
        return None

def normalize_target(raw):
    raw = (raw or "").strip().strip(").,;\"'")
    if not raw:
        return None

    if raw.lower().startswith(("http://", "https://")):
        return (("url", raw),)

    if RX_IPV4.fullmatch(raw):
        return (("ip", raw),)

    if RX_DOMAIN.fullmatch(raw.lower()):
        return (("domain", raw.lower()),)

    return None

def extract_targets_from_reports(reports):
    found = []
    for r in reports:
        blob = "\n".join([r.get("name") or "", r.get("description") or ""])
        for m in RX_URL.findall(blob):
            found.extend(normalize_target(m) or [])
        for m in RX_IPV4.findall(blob):
            found.extend(normalize_target(m) or [])
        for m in RX_DOMAIN.findall(blob):
            found.extend(normalize_target(m) or [])

    # URL → DOMAIN conversion happens here
    normalized = []
    for ttype, tval in found:
        if ttype == "url":
            d = url_to_domain(tval)
            if d:
                normalized.append(("domain", d))
        else:
            normalized.append((ttype, tval))

    # de-dup
    uniq = []
    seen = set()
    for t in normalized:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    return uniq

def run_spiderfoot_scan(target_value):
    os.makedirs(OUT_DIR, exist_ok=True)
    scan_id = hashlib.sha1(target_value.encode("utf-8")).hexdigest()[:12]
    out_file = os.path.join(OUT_DIR, f"sf_{scan_id}.json")

    cmd = ["python3", "/home/spiderfoot/sf.py", "-s", target_value, "-o", "json", "-max-threads", str(SF_MAX_THREADS)]
    if SF_MODULES.strip():
        cmd += ["-m", SF_MODULES.strip()]
    else:
        cmd += ["-u", SF_USECASE]

    log(f"Running SpiderFoot: {' '.join(cmd)}")
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=SF_TIMEOUT_SECONDS)
    stdout = (p.stdout or "").strip()
    stderr = (p.stderr or "").strip()

    if not stdout:
        return None, f"No stdout. stderr:\n{stderr[-1500:]}"

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(stdout + "\n")
    return out_file, None

# -------------------------
# Main loop
# -------------------------
def main_loop():
    os.makedirs(OUT_DIR, exist_ok=True)
    state = load_state()
    ensure_label()
    log("started")

    while True:
        try:
            reports = fetch_recent_reports(limit=REPORT_LIMIT)
            unseen = [r for r in reports if r["id"] not in state.get("seen_reports", [])]
            for r in unseen:
                state.setdefault("seen_reports", []).append(r["id"])

            targets = extract_targets_from_reports(unseen)
            seen = set(state.get("seen_targets", []))
            targets = [t for t in targets if f"{t[0]}:{t[1]}" not in seen]
            targets = targets[:SF_MAX_TARGETS_PER_CYCLE]

            if not targets:
                log("no new targets")
                save_state(state)
                time.sleep(RUN_EVERY)
                continue

            log(f"targets to scan: {targets}")

            for ttype, tval in targets:
                state.setdefault("seen_targets", []).append(f"{ttype}:{tval}")
                out_file, err = run_spiderfoot_scan(tval)
                if err:
                    log(f"scan failed: {err}")
                else:
                    log(f"scan complete: {out_file}")

            save_state(state)

        except Exception as e:
            log(f"error: {e}")

        time.sleep(RUN_EVERY)

if __name__ == "__main__":
    main_loop()
 
