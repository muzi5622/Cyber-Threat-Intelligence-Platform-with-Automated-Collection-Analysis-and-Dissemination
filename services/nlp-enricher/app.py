import os
import time
import re
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta

import requests


# -------------------------
# Config
# -------------------------
OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "120"))

# Optional: process each report only once
STATE_DB = os.getenv("NLP_STATE_DB", "")  # e.g. /state/nlp.db
MAX_AGE_DAYS = int(os.getenv("NLP_MAX_AGE_DAYS", "14"))
FETCH_LIMIT = int(os.getenv("NLP_FETCH_LIMIT", "20"))

EXTRACT_LABEL = os.getenv("NLP_LABEL", "auto-extracted")
CREATE_INDICATOR = os.getenv("NLP_CREATE_INDICATOR", "true").lower() in ("1", "true", "yes")

# Avoid treating file extensions as "domains"
IGNORE_TLDS = set(
    x.strip().lower()
    for x in os.getenv("NLP_IGNORE_TLDS", "html,htm,php,aspx,jsp").split(",")
    if x.strip()
)

GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}


# -------------------------
# IOC regex patterns
# -------------------------
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>()\"']+\b", re.IGNORECASE),
    # Domain: requires at least one dot + a valid-ish TLD (2-24 chars)
    "domain": re.compile(r"\b(?=.{4,253}\b)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}


# -------------------------
# GraphQL helper
# -------------------------
def gql(query: str, variables=None):
    r = requests.post(
        GQL,
        headers=HEADERS,
        json={"query": query, "variables": variables or {}},
        timeout=45,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]


# -------------------------
# State DB (optional)
# -------------------------
def state_init():
    if not STATE_DB:
        return None
    os.makedirs(os.path.dirname(STATE_DB), exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed (
          id TEXT PRIMARY KEY,
          processed_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def state_has(conn, key: str) -> bool:
    if conn is None:
        return False
    cur = conn.execute("SELECT 1 FROM processed WHERE id = ?", (key,))
    return cur.fetchone() is not None


def state_put(conn, key: str):
    if conn is None:
        return
    conn.execute(
        "INSERT OR REPLACE INTO processed (id, processed_at) VALUES (?, ?)",
        (key, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def stable_key(report_id: str) -> str:
    return hashlib.sha256(report_id.encode("utf-8")).hexdigest()


def within_age(created_at_str: str) -> bool:
    try:
        dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
    except Exception:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    return dt >= cutoff


# -------------------------
# Fetch recent reports
# -------------------------
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


# -------------------------
# Scoring
# -------------------------
def confidence_score(ioc_type: str, value: str) -> int:
    base = 50
    if ioc_type in ("sha256", "sha1", "md5"):
        base += 20
    if ioc_type in ("ipv4", "ipv6"):
        base += 10
    if ioc_type == "url":
        base += 5
    if ioc_type == "domain" and value.count(".") >= 2:
        base += 5
    if ioc_type == "cve":
        base += 10
    return min(base, 95)


# -------------------------
# OpenCTI: Label
# -------------------------
def create_label(value: str):
    q = """
    mutation CreateLabel($input: LabelAddInput!) {
      labelAdd(input: $input) { id value }
    }
    """
    try:
        return gql(q, {"input": {"value": value}})["labelAdd"]["id"]
    except Exception:
        # If exists, fetch it
        q2 = """
        query Labels($search: String!) {
          labels(search: $search, first: 1) { edges { node { id value } } }
        }
        """
        d = gql(q2, {"search": value})
        edges = d.get("labels", {}).get("edges", [])
        if edges:
            return edges[0]["node"]["id"]
        raise


# -------------------------
# OpenCTI: Vulnerability (CVE)
# -------------------------
def vulnerability_add(name: str, score: int):
    q = """
    mutation Vuln($name: String!, $score: Int!) {
      vulnerabilityAdd(input: { name: $name, x_opencti_score: $score }) { id }
    }
    """
    return gql(q, {"name": name, "score": score})["vulnerabilityAdd"]["id"]


# -------------------------
# OpenCTI: Observables (polymorphic + correct StixFile hashes)
# -------------------------
def observable_add(obs_type: str, value: str, score: int, label_values=None):
    label_values = label_values or []

    # Hashes -> StixFile with hashes: [HashInput]
    if obs_type == "StixFile":
        algo = "MD5" if len(value) == 32 else "SHA-1" if len(value) == 40 else "SHA-256"
        q = """
        mutation FileObs($type: String!, $score: Int!, $algo: String!, $hash: String!, $labels: [String!], $ci: Boolean) {
          stixCyberObservableAdd(
            type: $type,
            x_opencti_score: $score,
            createIndicator: $ci,
            objectLabel: $labels,
            StixFile: { hashes: [{ algorithm: $algo, hash: $hash }] }
          ) { id }
        }
        """
        return gql(
            q,
            {
                "type": "StixFile",
                "score": score,
                "algo": algo,
                "hash": value,
                "labels": label_values,
                "ci": CREATE_INDICATOR,
            },
        )["stixCyberObservableAdd"]["id"]

    # Non-hash observables use correct per-type AddInput objects
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
    mutation Obs($type: String!, $score: Int!, $val: String!, $labels: [String!], $ci: Boolean) {{
      stixCyberObservableAdd(
        type: $type,
        x_opencti_score: $score,
        createIndicator: $ci,
        objectLabel: $labels,
        {input_key}: {{ value: $val }}
      ) {{ id }}
    }}
    """
    return gql(
        q,
        {"type": obs_type, "score": score, "val": value, "labels": label_values, "ci": CREATE_INDICATOR},
    )["stixCyberObservableAdd"]["id"]


# -------------------------
# IOC extraction + normalization
# -------------------------
def normalize_iocs(found):
    out = []
    seen = set()

    for ioc_type, val in found:
        t = ioc_type.lower()
        v = val.strip()

        if t == "domain":
            tld = v.rsplit(".", 1)[-1].lower()
            if tld in IGNORE_TLDS:
                continue

        key = (t, v.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append((t, v))

    return out


def map_ioc_to_obs_type(ioc_type: str) -> str:
    if ioc_type == "ipv4":
        return "IPv4-Addr"
    if ioc_type == "ipv6":
        return "IPv6-Addr"
    if ioc_type == "domain":
        return "Domain-Name"
    if ioc_type == "url":
        return "Url"
    if ioc_type in ("md5", "sha1", "sha256"):
        return "StixFile"
    return "Artifact"


# -------------------------
# Main loop
# -------------------------
def main_loop():
    if not OPENCTI_TOKEN:
        raise RuntimeError("OPENCTI_TOKEN is empty. Set OPENCTI_TOKEN env var.")

    conn = state_init()
    label_id = None

    print("[nlp-enricher] started", flush=True)

    while True:
        try:
            reports = fetch_recent_reports(limit=FETCH_LIMIT)

            if not reports:
                print("[nlp-enricher] no reports found yet", flush=True)
                time.sleep(RUN_EVERY)
                continue

            # Ensure label exists once
            if label_id is None and EXTRACT_LABEL:
                try:
                    label_id = create_label(EXTRACT_LABEL)
                    print(f"[nlp-enricher] label ready: {EXTRACT_LABEL}", flush=True)
                except Exception as e:
                    print("[nlp-enricher] label ensure failed:", e, flush=True)
                    label_id = None

            for rep in reports:
                rid = rep.get("id")
                if not rid:
                    continue

                if not within_age(rep.get("created_at", "")):
                    continue

                skey = stable_key(rid)
                if state_has(conn, skey):
                    continue

                text_blob = (rep.get("name") or "") + "\n" + (rep.get("description") or "")

                found = []
                for t, rx in IOC_PATTERNS.items():
                    for m in rx.findall(text_blob):
                        found.append((t, m))

                iocs = normalize_iocs(found)
                if not iocs:
                    state_put(conn, skey)
                    continue

                print(f"[nlp-enricher] found {len(iocs)} IOCs -> pushing to OpenCTI", flush=True)

                label_values = [EXTRACT_LABEL] if EXTRACT_LABEL else []

                for ioc_type, val in iocs:
                    score = confidence_score(ioc_type, val)

                    # CVE as Vulnerability (domain object)
                    if ioc_type == "cve":
                        try:
                            vulnerability_add(val.upper(), score)
                        except Exception as e:
                            print("[nlp-enricher] vuln push failed:", e, flush=True)
                        continue

                    obs_type = map_ioc_to_obs_type(ioc_type)

                    try:
                        observable_add(obs_type, val, score, label_values=label_values)
                    except Exception as e:
                        # duplicates / schema mismatches show here
                        print("[nlp-enricher] observable push failed:", e, flush=True)

                state_put(conn, skey)

        except Exception as e:
            print("[nlp-enricher] error:", e, flush=True)

        time.sleep(RUN_EVERY)


if __name__ == "__main__":
    main_loop()
  
