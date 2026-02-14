import os
import re
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline



# At the very top
MODEL_PATH = os.getenv("MODEL_PATH", "muzi5622/cti-ner-model").strip()

# build_ner() uses MODEL_PATH
def build_ner():
    print(f"[ml-ner-enricher] downloading/loading model {MODEL_PATH} ...")

    tok = AutoTokenizer.from_pretrained(MODEL_PATH, use_fast=True)
    mdl = AutoModelForTokenClassification.from_pretrained(MODEL_PATH)

    # Fix for DistilBERT / models that don't use token_type_ids
    if hasattr(tok, "model_input_names") and "token_type_ids" in tok.model_input_names:
        tok.model_input_names = [n for n in tok.model_input_names if n != "token_type_ids"]

    orig_forward = mdl.forward
    def forward_drop_token_type_ids(*args, **kwargs):
        kwargs.pop("token_type_ids", None)
        return orig_forward(*args, **kwargs)
    mdl.forward = forward_drop_token_type_ids

    return pipeline(
        "token-classification",
        model=mdl,
        tokenizer=tok,
        aggregation_strategy="simple",
        device=-1,  # CPU
    )


# -------------------------
# Config
# -------------------------
OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "").strip()

MODEL_PATH = os.getenv("MODEL_PATH", "/app/models/cti_ner_model_n").strip()
NER_THRESHOLD = float(os.getenv("NER_THRESHOLD", "0.55"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))

CREATE_OBSERVABLES = os.getenv("CREATE_OBSERVABLES", "true").lower() in ("1", "true", "yes")
STATE_PATH = os.getenv("STATE_PATH", "/data/state.json")

# Relationship type that is supported in YOUR OpenCTI for reportEdit.relationAdd
REPORT_REL_TYPES = [x.strip() for x in os.getenv("REPORT_REL_TYPES", "object").split(",") if x.strip()]

# Regex fallback IOCs (reliable)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?=.{4,253}\b)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Avoid common “fake domains” like file extensions
IGNORE_TLDS = set(
    x.strip().lower()
    for x in os.getenv("NLP_IGNORE_TLDS", "html,htm,php,aspx,jsp").split(",")
    if x.strip()
)


# -------------------------
# OpenCTI client (GraphQL)
# -------------------------
class OpenCTIClient:
    def __init__(self, base: str, token: str):
        if not token:
            raise RuntimeError("OPENCTI_TOKEN is missing/empty")
        self.endpoint = f"{base}/graphql"
        self.s = requests.Session()
        self.s.headers.update(
            {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        )

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        r = self.s.post(self.endpoint, json={"query": query, "variables": variables or {}}, timeout=45)
        r.raise_for_status()
        data = r.json()
        if "errors" in data and data["errors"]:
            raise RuntimeError(f"OpenCTI GraphQL error: {data['errors']}")
        return data["data"]


# -------------------------
# State
# -------------------------
def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"processed_report_ids": []}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(path: str, state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


# -------------------------
# GraphQL: Reports + Relations + Observables
# -------------------------
QUERY_REPORTS = """
query Reports($first: Int!, $filters: FilterGroup) {
  reports(first: $first, filters: $filters, orderBy: created_at, orderMode: desc) {
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

# ✅ Your schema expects report(id: String!) for query
QUERY_REPORT_ONE = """
query OneReport($id: String!) {
  report(id: $id) {
    id
    name
    created_at
  }
}
"""

# ✅ CONFIRMED WORKING on your OpenCTI:
# - reportEdit(id: ID!)
# - relationAdd(...) MUST return { id }
# - relationship_type supported: "object"
MUT_REPORT_RELATION_ADD = """
mutation($id: ID!, $toId: StixRef!, $t: String!) {
  reportEdit(id: $id) {
    relationAdd(input: { toId: $toId, relationship_type: $t }) {
      id
    }
  }
}
"""

# Observable add: same working style as your nlp-enricher
MUT_OBS_FILE = """
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

def mut_obs_generic(input_key: str) -> str:
    return f"""
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


# -------------------------
# Helpers
# -------------------------
def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def make_time_filter(lookback_hours: int) -> Dict[str, Any]:
    start = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    return {
        "mode": "and",
        "filters": [{"key": "created_at", "values": [start], "operator": "gte"}],
        "filterGroups": [],
    }

def fetch_recent_reports(client: OpenCTIClient, lookback_hours: int, first: int) -> List[Dict[str, Any]]:
    filters = make_time_filter(lookback_hours)
    data = client.graphql(QUERY_REPORTS, {"first": first, "filters": filters})
    return [e["node"] for e in data["reports"]["edges"]]

def confidence_score(ioc_type: str, value: str) -> int:
    base = 50
    if ioc_type in ("sha256", "sha1", "md5"):
        base += 20
    if ioc_type == "ipv4":
        base += 10
    if ioc_type == "url":
        base += 5
    if ioc_type == "domain" and value.count(".") >= 2:
        base += 5
    if ioc_type == "cve":
        base += 10
    return min(base, 95)

def normalize_word(w: str) -> str:
    w = (w or "").strip()
    w = re.sub(r"\s+", " ", w)
    return w

def safe_label(s: str) -> str:
    s = normalize_word(s)
    return s[:80]

def entity_to_labels(ents: List[Dict[str, Any]]) -> List[str]:
    types = sorted(set(e["type"] for e in ents))
    labels = ["enriched:ml-ner"] + [f"ml:{t}" for t in types]
    return [safe_label(x) for x in labels if x]


# -------------------------
# NER pipeline (fix token_type_ids)
# -------------------------
def build_ner():
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, use_fast=True)

    # Some tokenizers still include token_type_ids even if model doesn't use them
    if hasattr(tok, "model_input_names") and "token_type_ids" in tok.model_input_names:
        tok.model_input_names = [n for n in tok.model_input_names if n != "token_type_ids"]

    mdl = AutoModelForTokenClassification.from_pretrained(MODEL_PATH)

    # ✅ HARD FIX: DistilBERT does not accept token_type_ids
    orig_forward = mdl.forward
    def forward_drop_token_type_ids(*args, **kwargs):
        kwargs.pop("token_type_ids", None)
        return orig_forward(*args, **kwargs)
    mdl.forward = forward_drop_token_type_ids

    return pipeline(
        "token-classification",
        model=mdl,
        tokenizer=tok,
        aggregation_strategy="simple",
        device=-1,  # CPU
    )

def extract_entities(ner_pipe: Any, text: str, threshold: float) -> List[Dict[str, Any]]:
    preds = ner_pipe(text)
    out: List[Dict[str, Any]] = []
    for p in preds:
        score = float(p.get("score", 0.0))
        if score < threshold:
            continue
        ent_type = str(p.get("entity_group") or p.get("entity") or "").upper()
        word = normalize_word(str(p.get("word", "")))
        if not ent_type or not word:
            continue
        out.append({"type": ent_type, "text": word, "score": score})
    return out

def fallback_iocs(text: str) -> Dict[str, List[str]]:
    domains: List[str] = []
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0)
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in IGNORE_TLDS:
            continue
        domains.append(d)

    return {
        "cve": sorted(set(m.group(0).upper() for m in CVE_RE.finditer(text))),
        "ipv4": sorted(set(m.group(0) for m in IPV4_RE.finditer(text))),
        "url": sorted(set(m.group(0) for m in URL_RE.finditer(text))),
        "domain": sorted(set(domains)),
        "sha256": sorted(set(m.group(0).lower() for m in SHA256_RE.finditer(text))),
        "sha1": sorted(set(m.group(0).lower() for m in SHA1_RE.finditer(text))),
        "md5": sorted(set(m.group(0).lower() for m in MD5_RE.finditer(text))),
    }


# -------------------------
# OpenCTI push (observables + relation to report)
# -------------------------
def report_relate(client: OpenCTIClient, report_id: str, to_id: str) -> Optional[str]:
    """
    Attach an object to the report.
    Your OpenCTI supports relationship_type="object".
    We also allow REPORT_REL_TYPES list just in case you add more later.
    """
    last_err: Optional[Exception] = None
    for rel_type in REPORT_REL_TYPES:
        try:
            d = client.graphql(MUT_REPORT_RELATION_ADD, {"id": report_id, "toId": to_id, "t": rel_type})
            return d["reportEdit"]["relationAdd"]["id"]
        except Exception as e:
            last_err = e
            continue

    if last_err is not None:
        print(f"[ml-ner-enricher] relate failed report={report_id} to={to_id} err={last_err}", flush=True)
    return None

def observable_add(client: OpenCTIClient, obs_type: str, value: str, score: int, label_values: List[str]) -> str:
    create_indicator = False  # keep false unless you want to generate indicators

    if obs_type == "StixFile":
        algo = "MD5" if len(value) == 32 else "SHA-1" if len(value) == 40 else "SHA-256"
        d = client.graphql(
            MUT_OBS_FILE,
            {
                "type": "StixFile",
                "score": score,
                "algo": algo,
                "hash": value,
                "labels": label_values,
                "ci": create_indicator,
            },
        )
        return d["stixCyberObservableAdd"]["id"]

    input_key = {
        "IPv4-Addr": "IPv4Addr",
        "Domain-Name": "DomainName",
        "Url": "Url",
    }.get(obs_type, "Artifact")

    q = mut_obs_generic(input_key)
    d = client.graphql(
        q,
        {"type": obs_type, "score": score, "val": value, "labels": label_values, "ci": create_indicator},
    )
    return d["stixCyberObservableAdd"]["id"]

def map_ioc_to_obs_type(ioc_type: str) -> str:
    if ioc_type == "ipv4":
        return "IPv4-Addr"
    if ioc_type == "domain":
        return "Domain-Name"
    if ioc_type == "url":
        return "Url"
    if ioc_type in ("md5", "sha1", "sha256"):
        return "StixFile"
    return "Artifact"


# -------------------------
# Main processing
# -------------------------
def process_report(client: OpenCTIClient, ner_pipe: Any, report: Dict[str, Any]) -> None:
    report_id = report["id"]
    title = report.get("name") or ""
    desc = report.get("description") or ""
    text = f"{title}\n{desc}".strip()
    if not text:
        return

    ents = extract_entities(ner_pipe, text, NER_THRESHOLD)
    labels = entity_to_labels(ents)

    if not CREATE_OBSERVABLES:
        return

    iocs = fallback_iocs(text)

    extra_labels: List[str] = []
    if iocs["cve"]:
        extra_labels.append("ml:HAS_CVE")
    label_values = sorted(set(labels + extra_labels))

    # Create observables and attach them to the report via relationAdd(object)
    for ioc_type, values in iocs.items():
        if ioc_type == "cve":
            # keep CVE handling in your nlp-enricher (vulnerabilityAdd) if you want
            continue

        obs_type = map_ioc_to_obs_type(ioc_type)
        for v in values[:30]:
            score = confidence_score(ioc_type, v)
            try:
                oid = observable_add(client, obs_type, v, score, label_values)
                report_relate(client, report_id, oid)
            except Exception as e:
                print(f"[ml-ner-enricher] observable_add failed type={obs_type} value={v} err={e}", flush=True)


def main() -> None:
    print(f"[ml-ner-enricher] starting at {iso_now()}", flush=True)
    print(f"[ml-ner-enricher] OPENCTI_BASE={OPENCTI_BASE}", flush=True)
    print(f"[ml-ner-enricher] MODEL_PATH={MODEL_PATH}", flush=True)
    print(f"[ml-ner-enricher] threshold={NER_THRESHOLD} poll={POLL_SECONDS}s lookback={LOOKBACK_HOURS}h", flush=True)
    print(f"[ml-ner-enricher] create_observables={CREATE_OBSERVABLES}", flush=True)
    print(f"[ml-ner-enricher] REPORT_REL_TYPES={REPORT_REL_TYPES}", flush=True)
    print(f"[ml-ner-enricher] state={STATE_PATH}", flush=True)

    client = OpenCTIClient(OPENCTI_BASE, OPENCTI_TOKEN)
    ner_pipe = build_ner()

    state = load_state(STATE_PATH)
    processed = set(state.get("processed_report_ids", []))

    while True:
        try:
            reports = fetch_recent_reports(client, LOOKBACK_HOURS, BATCH_SIZE)
            new_count = 0

            for r in reports:
                rid = r["id"]
                if rid in processed:
                    continue

                process_report(client, ner_pipe, r)

                processed.add(rid)
                new_count += 1

            if new_count:
                state["processed_report_ids"] = list(processed)[-5000:]
                save_state(STATE_PATH, state)

            print(f"[ml-ner-enricher] cycle done new={new_count} processed_total={len(processed)}", flush=True)

        except Exception as e:
            print(f"[ml-ner-enricher] ERROR: {e}", flush=True)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
