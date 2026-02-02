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
OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "300"))
REPORT_LIMIT = int(os.getenv("REPORT_LIMIT", "30"))

SF_TIMEOUT_SECONDS = int(os.getenv("SF_TIMEOUT_SECONDS", "300"))
SF_MODULES = os.getenv("SF_MODULES", "").strip()
SF_MAX_THREADS = int(os.getenv("SF_MAX_THREADS", "10"))
SF_MAX_TARGETS_PER_CYCLE = int(os.getenv("SF_MAX_TARGETS_PER_CYCLE", "3"))

STATE_PATH = os.getenv("STATE_PATH", "/data/state.json")
OUT_DIR = os.getenv("OUT_DIR", "/data/scans")

WAIT_OPENCTI_SECONDS = int(os.getenv("WAIT_OPENCTI_SECONDS", "300"))
ENRICH_MAX_NEW_OBSERVABLES = int(os.getenv("ENRICH_MAX_NEW_OBSERVABLES", "200"))

# Label value used on created observables
LABEL_VALUE = os.getenv("ENRICH_LABEL_VALUE", "spiderfoot-enriched")

GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json",
}

# -------------------------
# Regexes
# -------------------------
RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RX_DOMAIN = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RX_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# -------------------------
# SpiderFoot -> OpenCTI observable type mapping
# -------------------------
SF_TO_OPENCTI_TYPE = {
    "IP Address": "IPv4-Addr",
    "IPv6 Address": "IPv6-Addr",
    "Domain Name": "Domain-Name",
    "Internet Name": "Domain-Name",
    "Hostname": "Hostname",
    "URL": "Url",
    "Email Address": "Email-Addr",
}

# -------------------------
# Logging
# -------------------------
def log(msg):
    print(f"[spiderfoot-automation] {msg}", flush=True)

# -------------------------
# GraphQL helper
# -------------------------
def gql(query, variables=None):
    r = requests.post(
        GQL,
        headers=HEADERS,
        json={"query": query, "variables": variables or {}},
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

# -------------------------
# Wait for OpenCTI
# -------------------------
def wait_opencti():
    deadline = time.time() + WAIT_OPENCTI_SECONDS
    while time.time() < deadline:
        try:
            requests.get(OPENCTI_BASE, timeout=5)
            q = "query { reports(first: 1) { edges { node { id }}}}"
            requests.post(GQL, headers=HEADERS, json={"query": q}, timeout=10).raise_for_status()
            log("OpenCTI reachable")
            return
        except Exception:
            time.sleep(3)
    raise RuntimeError("OpenCTI not reachable")

# -------------------------
# State
# -------------------------
def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {"seen_reports": [], "seen_targets": [], "seen_enrich": []}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)

# -------------------------
# Reports
# -------------------------
def fetch_recent_reports(limit=20):
    q = """
    query Reports($first: Int!) {
      reports(first: $first, orderBy: created_at, orderMode: desc) {
        edges { node { id name description } }
      }
    }
    """
    d = gql(q, {"first": limit})
    return [e["node"] for e in d["reports"]["edges"]]

# -------------------------
# Target extraction
# -------------------------
def url_to_domain(u):
    try:
        if "://" not in u:
            u = "http://" + u
        p = urlparse(u)
        return p.hostname.lower()
    except Exception:
        return None

def extract_targets_from_reports(reports):
    found = []
    for r in reports:
        blob = (r.get("name", "") + "\n" + (r.get("description") or ""))
        for m in RX_URL.findall(blob):
            found.append(("url", m))
        for m in RX_IPV4.findall(blob):
            found.append(("ip", m))
        for m in RX_DOMAIN.findall(blob):
            found.append(("domain", m.lower()))

    normalized = []
    for t, v in found:
        if t == "url":
            d = url_to_domain(v)
            if d:
                normalized.append(("domain", d))
        else:
            normalized.append((t, v))

    return list(set(normalized))

# -------------------------
# SpiderFoot runner
# -------------------------
def run_spiderfoot_scan(target):
    os.makedirs(OUT_DIR, exist_ok=True)
    scan_id = hashlib.sha1(target.encode()).hexdigest()[:12]
    out_file = f"{OUT_DIR}/sf_{scan_id}.json"

    cmd = ["python3", "/home/spiderfoot/sf.py", "-s", target, "-o", "json", "-max-threads", str(SF_MAX_THREADS)]
    if SF_MODULES:
        cmd += ["-m", SF_MODULES]

    log("Running: " + " ".join(cmd))
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=SF_TIMEOUT_SECONDS,
    )

    if not p.stdout:
        if p.stderr:
            log(f"SpiderFoot stderr: {p.stderr.strip()[:400]}")
        return None

    with open(out_file, "w") as f:
        f.write(p.stdout)
    return out_file

def parse_spiderfoot_json(path):
    raw = open(path).read().strip()
    try:
        return json.loads(raw)
    except Exception:
        out = []
        for line in raw.splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out

def spiderfoot_findings_to_observables(events):
    out = []
    for ev in events:
        typ = ev.get("type")
        val = ev.get("data")
        if not typ or not val:
            continue
        otype = SF_TO_OPENCTI_TYPE.get(typ)
        if not otype:
            continue
        sval = str(val).strip()
        if otype == "Url" and not sval.startswith("http"):
            sval = "http://" + sval
        out.append((otype, sval))
    return list(set(out))

# -------------------------
# OpenCTI label ensure (by value)
# -------------------------
def ensure_label_exists():
    """
    Ensure LABEL_VALUE exists as a Label in OpenCTI.
    We don't need the ID because we attach by value using objectLabel.
    """
    q_find = """
    query FindLabel($search: String!) {
      labels(search: $search, first: 1) { edges { node { id value } } }
    }
    """
    d = gql(q_find, {"search": LABEL_VALUE})
    edges = d["labels"]["edges"]
    if edges:
        return edges[0]["node"]["id"]

    q_add = """
    mutation CreateLabel($input: LabelAddInput!) {
      labelAdd(input: $input) { id value }
    }
    """
    d = gql(q_add, {"input": {"value": LABEL_VALUE, "color": "#03a9f4"}})
    return d["labelAdd"]["id"]

# -------------------------
# OpenCTI observable creation (polymorphic)
# -------------------------
def create_observable(obs_type: str, value: str):
    """
    Create an observable using OpenCTI's polymorphic stixCyberObservableAdd,
    attaching objectLabel by VALUE (LABEL_VALUE).
    """
    obs_type = (obs_type or "").strip()
    value = (value or "").strip()
    if not obs_type or not value:
        return None

    input_key = {
        "IPv4-Addr": "IPv4Addr",
        "IPv6-Addr": "IPv6Addr",
        "Domain-Name": "DomainName",
        "Url": "Url",
        "Email-Addr": "EmailAddr",
        "Hostname": "Hostname",
        "Artifact": "Artifact",
    }.get(obs_type, "Artifact")

    q = f"""
    mutation Obs($type: String!, $val: String!, $labels: [String!]) {{
      stixCyberObservableAdd(
        type: $type,
        objectLabel: $labels,
        {input_key}: {{ value: $val }}
      ) {{
        id
      }}
    }}
    """

    d = gql(q, {"type": obs_type, "val": value, "labels": [LABEL_VALUE]})
    return d["stixCyberObservableAdd"]["id"]

# -------------------------
# Main loop
# -------------------------
def main_loop():
    wait_opencti()
    ensure_label_exists()
    state = load_state()
    log("Started")

    while True:
        try:
            reports = fetch_recent_reports(REPORT_LIMIT)

            unseen = [r for r in reports if r["id"] not in state["seen_reports"]]
            for r in unseen:
                state["seen_reports"].append(r["id"])

            targets = extract_targets_from_reports(unseen)

            # Deduplicate vs state
            targets = [t for t in targets if f"{t[0]}:{t[1]}" not in state["seen_targets"]]
            targets = targets[:SF_MAX_TARGETS_PER_CYCLE]

            if not targets:
                log("No new targets")
                save_state(state)
                time.sleep(RUN_EVERY)
                continue

            for ttype, target in targets:
                state["seen_targets"].append(f"{ttype}:{target}")

                out_file = run_spiderfoot_scan(target)
                if not out_file:
                    continue

                events = parse_spiderfoot_json(out_file)
                obs = spiderfoot_findings_to_observables(events)

                created_this_cycle = 0
                for otype, value in obs:
                    if created_this_cycle >= ENRICH_MAX_NEW_OBSERVABLES:
                        break

                    key = f"{otype}:{value}"
                    if key in state["seen_enrich"]:
                        continue

                    try:
                        oid = create_observable(otype, value)
                        if oid:
                            state["seen_enrich"].append(key)
                            created_this_cycle += 1
                            log(f"Created {otype} {value}")
                    except Exception as e:
                        log(f"create_observable failed for {otype}={value}: {e}")

            save_state(state)

        except Exception as e:
            log(f"ERROR: {e}")

        time.sleep(RUN_EVERY)

if __name__ == "__main__":
    main_loop()
 
