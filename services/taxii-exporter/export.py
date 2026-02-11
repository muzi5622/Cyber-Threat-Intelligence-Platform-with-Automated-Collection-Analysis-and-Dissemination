import os, time, json, re
from datetime import datetime, timezone, timedelta

import requests
import yaml

OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
EXPORT_DIR = os.getenv("EXPORT_DIR", "/exports")
RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "300"))

# Policy file that defines partner/public/internal sharing rules
POLICY_PATH = os.getenv("SHARE_POLICY_PATH", "/app/policies/partners.yml")

# Defaults
DEFAULT_PARTNER_NAME = os.getenv("EXPORT_PARTNER_NAME", "bank")
DEFAULT_LOOKBACK_DAYS = int(os.getenv("EXPORT_LOOKBACK_DAYS", "7"))
DEFAULT_MAX_OBS = int(os.getenv("EXPORT_MAX_OBSERVABLES", "800"))
DEFAULT_MAX_REPORTS = int(os.getenv("EXPORT_MAX_REPORTS", "50"))

HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}"}


# ---------------------------
# Policies / utilities
# ---------------------------
def load_policies(path: str) -> dict:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return data.get("partners", data)
    except Exception as e:
        print("[taxii-exporter] policy load error:", e)
        return {}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def within_lookback(iso_dt: str, lookback_days: int = DEFAULT_LOOKBACK_DAYS) -> bool:
    if not iso_dt:
        return True
    try:
        dt = datetime.fromisoformat(iso_dt.replace("Z", "+00:00"))
    except Exception:
        return True
    return dt >= (datetime.now(timezone.utc) - timedelta(days=lookback_days))


def labels_lower(obj: dict) -> list:
    labs = obj.get("objectLabel") or []
    out = []
    for l in labs:
        v = l.get("value")
        if v:
            out.append(v.lower())
    return out


def match_allowed_labels(obj: dict, allowed: list) -> bool:
    # If empty -> allow all
    if not allowed:
        return True
    allowed = [x.lower() for x in allowed]
    labs = set(labels_lower(obj))
    return any(a in labs for a in allowed)


def tlp_marking(tlp: str) -> dict:
    tlp = (tlp or "clear").strip().lower()
    tlp_id = {
        "clear": "marking-definition--tlp-clear",
        "white": "marking-definition--tlp-clear",
        "green": "marking-definition--tlp-green",
        "amber": "marking-definition--tlp-amber",
        "yellow": "marking-definition--tlp-amber",
        "red": "marking-definition--tlp-red",
    }.get(tlp, "marking-definition--tlp-amber")

    tlp_value = {
        "marking-definition--tlp-clear": "clear",
        "marking-definition--tlp-green": "green",
        "marking-definition--tlp-amber": "amber",
        "marking-definition--tlp-red": "red",
    }[tlp_id]

    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": tlp_id,
        "definition_type": "tlp",
        "definition": {"tlp": tlp_value},
    }


def is_otx_observable(node: dict) -> bool:
    cb = (node.get("createdBy") or {}).get("name") or ""
    cb = cb.lower()
    return ("alienvault" in cb) or ("otx" in cb)


def is_otx_report(rep: dict) -> bool:
    cb = (rep.get("createdBy") or {}).get("name") or ""
    cb = cb.lower()
    # Prefer createdBy when present
    if cb:
        return ("alienvault" in cb) or ("otx" in cb)
    # fallback heuristic on name/description
    text = ((rep.get("name") or "") + " " + (rep.get("description") or "")).lower()
    return ("alienvault" in text) or ("otx" in text) or ("otx.alienvault.com" in text)


def sanitize_text(s: str) -> str:
    if not s:
        return s
    # remove URLs
    s = re.sub(r"https?://\S+", "[redacted-url]", s)
    # remove email-like
    s = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", "[redacted-email]", s)
    return s


def sanitize_report(rep: dict) -> dict:
    # Remove sensitive provenance & sanitize text
    out = dict(rep)
    out.pop("createdBy", None)
    if "description" in out and out["description"]:
        out["description"] = sanitize_text(out["description"])
    return out


# ---------------------------
# OpenCTI fetchers
# ---------------------------
def fetch_observables(limit: int = 200) -> list:
    gql = f"{OPENCTI_BASE}/graphql"
    q = """
    query($n:Int!){
      stixCyberObservables(first:$n, orderBy: created_at, orderMode: desc){
        edges{
          node{
            id
            observable_value
            created_at
            createdBy { name }
            objectLabel { value }
          }
        }
      }
    }
    """
    r = requests.post(
        gql,
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"query": q, "variables": {"n": limit}},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        print("[taxii-exporter] fetch_observables GraphQL errors:", str(data["errors"])[:800])
        return []
    edges = data["data"]["stixCyberObservables"]["edges"]
    return [e["node"] for e in edges if e.get("node")]


def fetch_reports(limit: int = 50) -> list:
    gql = f"{OPENCTI_BASE}/graphql"
    q = """
    query($n:Int!){
      reports(first:$n, orderBy: created_at, orderMode: desc){
        edges{
          node{
            id
            name
            description
            created_at
            createdBy { name }
            objectLabel { value }
          }
        }
      }
    }
    """
    r = requests.post(
        gql,
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"query": q, "variables": {"n": limit}},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        print("[taxii-exporter] fetch_reports GraphQL errors:", str(data["errors"])[:800])
        return []
    edges = data["data"]["reports"]["edges"]
    return [e["node"] for e in edges if e.get("node")]


# ---------------------------
# STIX builders
# ---------------------------
def stix_indicator_for_value(val: str, stix_id_suffix: str, valid_from: str) -> dict:
    v = (val or "").strip()
    # Very lightweight type detection -> STIX patterns
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        pat = f"[ipv4-addr:value = '{v}']"
        name = f"IOC (ipv4-addr) {v}"
    elif re.match(r"^[a-fA-F0-9]{32}$", v):
        pat = f"[file:hashes.MD5 = '{v}']"
        name = f"IOC (md5) {v}"
    elif re.match(r"^[a-fA-F0-9]{40}$", v):
        pat = f"[file:hashes.SHA-1 = '{v}']"
        name = f"IOC (sha1) {v}"
    elif re.match(r"^[a-fA-F0-9]{64}$", v):
        pat = f"[file:hashes.SHA-256 = '{v}']"
        name = f"IOC (sha256) {v}"
    elif v.startswith("http://") or v.startswith("https://"):
        pat = f"[url:value = '{v}']"
        name = f"IOC (url) {v}"
    else:
        pat = f"[domain-name:value = '{v}']"
        name = f"IOC (domain-name) {v}"

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{stix_id_suffix}",
        "name": name,
        "pattern": pat,
        "pattern_type": "stix",
        "valid_from": valid_from,
    }


def stix_report(rep: dict, tlp_id: str, sanitize: bool) -> dict:
    rid = rep.get("id", "")
    suffix = rid[-12:] if rid else f"{abs(hash(rep.get('name','')))%10**12:012d}"
    published = rep.get("created_at") or now_utc_iso()
    desc = rep.get("description") or ""
    name = rep.get("name") or "Shared Report"

    if sanitize:
        desc = sanitize_text(desc)

    obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{suffix}",
        "name": name[:256],
        "description": desc[:5000],
        "published": published,
        "report_types": ["threat-report"],
        "object_marking_refs": [tlp_id],
    }
    return obj


# ---------------------------
# Export collections
# ---------------------------
def ensure_dirs():
    base = os.path.join(EXPORT_DIR, "share")
    os.makedirs(os.path.join(base, "public"), exist_ok=True)
    os.makedirs(os.path.join(base, "internal"), exist_ok=True)
    os.makedirs(os.path.join(base, "partners", DEFAULT_PARTNER_NAME), exist_ok=True)


def write_json(path: str, obj: dict):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def export_collections():
    ensure_dirs()
    policies = load_policies(POLICY_PATH)

    public = policies.get("public", {"tlp": "clear", "include_reports": False, "max_observables": 200, "sanitize_reports": True, "allowed_labels": []})
    internal = policies.get("internal", {"tlp": "red", "include_reports": True, "max_observables": 800, "max_reports": 50, "sanitize_reports": False, "allowed_labels": []})
    partner = policies.get(DEFAULT_PARTNER_NAME, {"tlp": "amber", "include_reports": True, "max_observables": 200, "max_reports": 20, "sanitize_reports": True, "allowed_labels": []})

    raw_obs = fetch_observables(limit=max(DEFAULT_MAX_OBS, int(internal.get("max_observables", 800))))
    raw_rep = fetch_reports(limit=max(DEFAULT_MAX_REPORTS, int(internal.get("max_reports", 50))))

    # lookback filter
    raw_obs = [o for o in raw_obs if within_lookback(o.get("created_at"), DEFAULT_LOOKBACK_DAYS)]
    raw_rep = [r for r in raw_rep if within_lookback(r.get("created_at"), DEFAULT_LOOKBACK_DAYS)]

    base_share = os.path.join(EXPORT_DIR, "share")

    # ---- PUBLIC (only indicators, no reports) ----
    pub_tlp_obj = tlp_marking(public.get("tlp", "clear"))
    pub_tlp_id = pub_tlp_obj["id"]
    pub_obs = raw_obs[: int(public.get("max_observables", 200))]

    pub_objects = [pub_tlp_obj]
    for o in pub_obs:
        val = o.get("observable_value") or ""
        sid = (o.get("id") or "")[-12:] or f"{abs(hash(val))%10**12:012d}"
        pub_objects.append(stix_indicator_for_value(val, sid, o.get("created_at") or now_utc_iso()))

    pub_bundle = {"type": "bundle", "id": "bundle--cti-share", "spec_version": "2.1", "objects": pub_objects}
    write_json(os.path.join(base_share, "public", "bundle.json"), pub_bundle)

    # ---- INTERNAL (indicators + reports, no sanitization) ----
    int_tlp_obj = tlp_marking(internal.get("tlp", "red"))
    int_tlp_id = int_tlp_obj["id"]

    int_obs = [o for o in raw_obs if match_allowed_labels(o, internal.get("allowed_labels", []))]
    int_obs = int_obs[: int(internal.get("max_observables", 800))]

    int_rep = [r for r in raw_rep if match_allowed_labels(r, internal.get("allowed_labels", []))]
    int_rep = int_rep[: int(internal.get("max_reports", 50))]

    int_objects = [int_tlp_obj]
    for o in int_obs:
        val = o.get("observable_value") or ""
        sid = (o.get("id") or "")[-12:] or f"{abs(hash(val))%10**12:012d}"
        int_objects.append(stix_indicator_for_value(val, sid, o.get("created_at") or now_utc_iso()))

    if internal.get("include_reports", True):
        for r in int_rep:
            int_objects.append(stix_report(r, int_tlp_id, sanitize=False))

    int_bundle = {"type": "bundle", "id": "bundle--cti-share", "spec_version": "2.1", "objects": int_objects}
    write_json(os.path.join(base_share, "internal", "reports.json"), int_bundle)

    # ---- PARTNER (OTX curated indicators + optional sanitized reports) ----
    p_tlp_obj = tlp_marking(partner.get("tlp", "amber"))
    p_tlp_id = p_tlp_obj["id"]

    # partner: only OTX indicators by createdBy
    p_obs = [o for o in raw_obs if is_otx_observable(o)]
    # optional label gating (usually empty -> allow)
    p_obs = [o for o in p_obs if match_allowed_labels(o, partner.get("allowed_labels", []))]
    p_obs = p_obs[: int(partner.get("max_observables", 200))]

    # partner: curated OTX reports (sanitized)
    p_rep = [r for r in raw_rep if is_otx_report(r)]
    p_rep = [r for r in p_rep if match_allowed_labels(r, partner.get("allowed_labels", []))]
    p_rep = p_rep[: int(partner.get("max_reports", 20))]

    p_objects = [p_tlp_obj]
    for o in p_obs:
        val = o.get("observable_value") or ""
        sid = (o.get("id") or "")[-12:] or f"{abs(hash(val))%10**12:012d}"
        p_objects.append(stix_indicator_for_value(val, sid, o.get("created_at") or now_utc_iso()))

    if partner.get("include_reports", True):
        for r in p_rep:
            # sanitize partner reports if configured
            sanitize = bool(partner.get("sanitize_reports", True))
            rr = sanitize_report(r) if sanitize else r
            p_objects.append(stix_report(rr, p_tlp_id, sanitize=sanitize))

    p_bundle = {"type": "bundle", "id": "bundle--cti-share", "spec_version": "2.1", "objects": p_objects}
    write_json(os.path.join(base_share, "partners", DEFAULT_PARTNER_NAME, "reports.json"), p_bundle)

    # index
    index = {
        "generated_at": now_utc_iso(),
        "lookback_days": DEFAULT_LOOKBACK_DAYS,
        "paths": {
            "public_bundle": "share/public/bundle.json",
            "partner_reports": f"share/partners/{DEFAULT_PARTNER_NAME}/reports.json",
            "internal_reports": "share/internal/reports.json",
        },
    }
    write_json(os.path.join(base_share, "index.json"), index)

    print("[taxii-exporter] wrote collections into /exports/share/")


def main():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    while True:
        try:
            export_collections()
        except Exception as e:
            print("[taxii-exporter] error:", e)
        time.sleep(RUN_EVERY)


if __name__ == "__main__":
    main()
