# ===============================
# ml-ner-enricher FULL CODE
# ===============================

import os
import re
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline


# -------------------------------------------------
# Config
# -------------------------------------------------

MODEL_PATH = os.getenv("MODEL_PATH", "muzi5622/cti-ner-model").strip()

OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "").strip()

NER_THRESHOLD = float(os.getenv("NER_THRESHOLD", "0.55"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))

CREATE_OBSERVABLES = os.getenv("CREATE_OBSERVABLES", "true").lower() in ("1", "true", "yes")

STATE_PATH = os.getenv("STATE_PATH", "/data/state.json")

REPORT_REL_TYPES = [
    x.strip()
    for x in os.getenv("REPORT_REL_TYPES", "object").split(",")
    if x.strip()
]


# -------------------------------------------------
# Regex IOC Detection
# -------------------------------------------------

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+\b", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"\b(?=.{4,253}\b)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b"
)

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

IGNORE_TLDS = set(
    x.strip().lower()
    for x in os.getenv("NLP_IGNORE_TLDS", "html,htm,php,aspx,jsp").split(",")
    if x.strip()
)


# -------------------------------------------------
# OpenCTI Client
# -------------------------------------------------

class OpenCTIClient:
    def __init__(self, base: str, token: str):
        if not token:
            raise RuntimeError("OPENCTI_TOKEN missing")

        self.endpoint = f"{base}/graphql"

        self.s = requests.Session()
        self.s.headers.update(
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            }
        )

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None):
        r = self.s.post(
            self.endpoint,
            json={"query": query, "variables": variables or {}},
            timeout=45,
        )
        r.raise_for_status()

        data = r.json()
        if "errors" in data and data["errors"]:
            raise RuntimeError(str(data["errors"]))

        return data["data"]


# -------------------------------------------------
# GraphQL Queries + Mutations
# -------------------------------------------------

QUERY_REPORTS = """
query Reports($first: Int!, $filters: FilterGroup) {
  reports(first: $first, filters: $filters, orderBy: created_at, orderMode: desc) {
    edges {
      node {
        id
        name
        description
      }
    }
  }
}
"""

QUERY_LABELS = """
query($search: String!, $first: Int!) {
  labels(first: $first, search: $search) {
    edges { node { id value } }
  }
}
"""

MUT_LABEL_ADD = """
mutation($input: LabelAddInput!) {
  labelAdd(input: $input) { id value }
}
"""

MUT_REPORT_LABELS_PATCH = """
mutation($id: ID!, $vals: [Any]!) {
  reportEdit(id: $id) {
    fieldPatch(input: { key: "objectLabel", value: $vals }) {
      id
    }
  }
}
"""

MUT_REPORT_RELATION_ADD = """
mutation($id: ID!, $toId: StixRef!, $t: String!) {
  reportEdit(id: $id) {
    relationAdd(input: { toId: $toId, relationship_type: $t }) {
      id
    }
  }
}
"""


# -------------------------------------------------
# Label Cache Layer
# -------------------------------------------------

_LABEL_CACHE: Dict[str, str] = {}


def get_or_create_label_id(client: OpenCTIClient, value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError("empty label")

    key = v.lower()

    if key in _LABEL_CACHE:
        return _LABEL_CACHE[key]

    data = client.graphql(
        QUERY_LABELS,
        {"search": v, "first": 50},
    )

    for e in data["labels"]["edges"]:
        node = e["node"]
        if (node.get("value") or "").strip().lower() == key:
            _LABEL_CACHE[key] = node["id"]
            return node["id"]

    d = client.graphql(
        MUT_LABEL_ADD,
        {"input": {"value": v}},
    )

    lid = d["labelAdd"]["id"]
    _LABEL_CACHE[key] = lid

    return lid


def ensure_label_ids(client: OpenCTIClient, label_values: List[str]) -> List[str]:
    ids: List[str] = []

    for lv in label_values:
        try:
            ids.append(get_or_create_label_id(client, lv))
        except Exception as e:
            print(
                f"[ml-ner-enricher] label ensure failed value={lv} err={e}",
                flush=True,
            )

    out = []
    seen = set()

    for x in ids:
        if x and x not in seen:
            out.append(x)
            seen.add(x)

    return out


def report_set_label_ids(
    client: OpenCTIClient,
    report_id: str,
    label_ids: List[str],
):
    if not label_ids:
        return

    client.graphql(
        MUT_REPORT_LABELS_PATCH,
        {"id": report_id, "vals": label_ids},
    )


# -------------------------------------------------
# Utilities
# -------------------------------------------------

def iso_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_word(w: str) -> str:
    return re.sub(r"\s+", " ", (w or "").strip())


def entity_to_labels(ents: List[Dict[str, Any]]) -> List[str]:
    types = sorted(set(e["type"] for e in ents))

    labels = ["enriched:ml-ner"] + [f"ml:{t}" for t in types]

    return [normalize_word(x)[:80] for x in labels if x]


# -------------------------------------------------
# NER Pipeline
# -------------------------------------------------

def build_ner():
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, use_fast=True)

    if hasattr(tok, "model_input_names") and "token_type_ids" in tok.model_input_names:
        tok.model_input_names = [
            n for n in tok.model_input_names if n != "token_type_ids"
        ]

    mdl = AutoModelForTokenClassification.from_pretrained(MODEL_PATH)

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
        device=-1,
    )


def extract_entities(ner_pipe, text: str, threshold: float):
    preds = ner_pipe(text)

    out = []

    for p in preds:
        if float(p.get("score", 0)) < threshold:
            continue

        ent_type = str(p.get("entity_group") or "").upper()
        word = normalize_word(str(p.get("word") or ""))

        if ent_type and word:
            out.append({"type": ent_type, "text": word})

    return out


# -------------------------------------------------
# IOC Detection
# -------------------------------------------------

def fallback_iocs(text: str) -> Dict[str, List[str]]:
    domains = []

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


# -------------------------------------------------
# Report Processing
# -------------------------------------------------

def process_report(client, ner_pipe, report):

    report_id = report["id"]

    text = f"{report.get('name','')}\n{report.get('description','')}".strip()
    if not text:
        return

    # ---- NER ----
    ents = extract_entities(ner_pipe, text, NER_THRESHOLD)
    label_values = entity_to_labels(ents)

    # ---- Resolve label IDs + patch report (IMPORTANT)
    label_ids = ensure_label_ids(client, label_values)

    try:
        report_set_label_ids(client, report_id, label_ids)

        print(
            f"[ml-ner-enricher] labeled report={report_id} labels={label_values}",
            flush=True,
        )

    except Exception as e:
        print(
            f"[ml-ner-enricher] report label patch failed report={report_id} err={e}",
            flush=True,
        )

    # Must be before return
    if not CREATE_OBSERVABLES:
        return

    # IOC enrichment logic can be added here if needed


# -------------------------------------------------
# Main Loop
# -------------------------------------------------

def main():
    print(f"[ml-ner-enricher] starting at {iso_now()}", flush=True)

    client = OpenCTIClient(OPENCTI_BASE, OPENCTI_TOKEN)
    ner_pipe = build_ner()

    while True:
        try:
            reports = client.graphql(
                QUERY_REPORTS,
                {"first": BATCH_SIZE, "filters": None},
            )

            for edge in reports["reports"]["edges"]:
                process_report(client, ner_pipe, edge["node"])

        except Exception as e:
            print(f"[ml-ner-enricher] ERROR: {e}", flush=True)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main() 
