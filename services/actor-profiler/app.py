import os
import time
import json
from datetime import datetime, timezone

import requests
import numpy as np
import pandas as pd
import joblib

from huggingface_hub import snapshot_download
from pycti import OpenCTIApiClient


# ===========================
# Config
# ===========================
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX = os.getenv("ES_INDEX", "honeypot-logs-*")

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://opencti:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

RUN_EVERY_SECONDS = int(os.getenv("RUN_EVERY_SECONDS", "300"))

HF_REPO_ID = os.getenv("HF_REPO_ID", "muzi5622/actor-profiler-model")
HF_TOKEN = os.getenv("HF_TOKEN")

STATE_PATH = os.getenv("STATE_PATH", "/state/state.json")


# ===========================
# State helpers
# ===========================
def load_state():
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)


# ===========================
# Load models from HF
# ===========================
def load_models_from_hf():
    local_dir = snapshot_download(
        repo_id=HF_REPO_ID,
        token=HF_TOKEN,
        local_dir="/tmp/actor-profiler-model",
    )
    best_bundle = joblib.load(os.path.join(local_dir, "best_actor_model.joblib"))
    cluster_bundle = joblib.load(os.path.join(local_dir, "actor_cluster_model.joblib"))
    return best_bundle, cluster_bundle


def _extract_model_and_cols(bundle, default_cols=None, bundle_name="bundle"):
    feature_cols = None
    model = None

    if isinstance(bundle, dict):
        print(f"{bundle_name} keys:", sorted(list(bundle.keys())))

        for k in ["model", "cluster_model", "clusterer", "estimator", "pipeline", "clf", "sk_model"]:
            if k in bundle:
                model = bundle[k]
                break

        for k in ["feature_cols", "features", "columns", "cols", "feature_columns", "input_features"]:
            if k in bundle and bundle[k] is not None:
                feature_cols = bundle[k]
                break
    else:
        model = bundle

    if feature_cols is None:
        feature_cols = default_cols

    if model is None:
        raise RuntimeError(f"Could not extract model from {bundle_name}. type={type(bundle)}")

    return model, feature_cols


# ===========================
# Fetch ES events
# ===========================
def fetch_events(es_url, since_ts=None):
    query = {
        "size": 10000,
        "sort": [{"@timestamp": "asc"}],
    }

    if since_ts:
        query["query"] = {"range": {"@timestamp": {"gte": since_ts.isoformat()}}}

    r = requests.post(
        f"{es_url.rstrip('/')}/{ES_INDEX}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        timeout=60,
    )
    r.raise_for_status()

    hits = r.json().get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]


# ===========================
# Helpers: safe nested get + field normalization
# ===========================
def get_in(d, path, default=None):
    """
    Safe nested dict getter:
      get_in(doc, ["source","ip"])
    """
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def normalize_doc_fields(doc: dict) -> dict:
    """
    Make sure we always have flat keys:
      - source_ip
      - destination_port
      - protocol
      - duration
    by extracting them from common ES/ECS nests too.
    """
    out = dict(doc)  # shallow copy

    # source ip (common variants)
    source_ip = (
        doc.get("source_ip")
        or doc.get("src_ip")
        or doc.get("ip")
        or get_in(doc, ["source", "ip"])
        or get_in(doc, ["client", "ip"])
        or get_in(doc, ["observer", "ip"])
    )
    if source_ip is not None:
        out["source_ip"] = str(source_ip)

    # destination port
    dst_port = (
        doc.get("destination_port")
        or doc.get("dest_port")
        or doc.get("dst_port")
        or get_in(doc, ["destination", "port"])
        or get_in(doc, ["server", "port"])
    )
    if dst_port is not None:
        out["destination_port"] = dst_port

    # protocol / transport
    proto = (
        doc.get("protocol")
        or doc.get("proto")
        or get_in(doc, ["network", "transport"])
        or get_in(doc, ["network", "protocol"])
    )
    if proto is not None:
        out["protocol"] = str(proto)

    # duration (ECS often: event.duration in ns)
    duration = (
        doc.get("duration")
        or get_in(doc, ["event", "duration"])
        or get_in(doc, ["session", "duration"])
    )
    if duration is not None:
        out["duration"] = duration

    return out


def ensure_col(df: pd.DataFrame, col: str, default=""):
    if col not in df.columns:
        df[col] = default
    df[col] = df[col].astype(str)
    return df


def extract_auth_fields(doc: dict) -> dict:
    attempts = doc.get("auth_attempts") or []
    usernames = []
    passwords = []
    for a in attempts:
        if isinstance(a, dict):
            if a.get("username") is not None:
                usernames.append(str(a.get("username")))
            if a.get("password") is not None:
                passwords.append(str(a.get("password")))

    doc["usernames_joined"] = " ".join(usernames)
    doc["passwords_joined"] = " ".join(passwords)
    doc["auth_attempts_count"] = len(attempts)
    return doc


# ===========================
# Feature builder (improved)
# ===========================
def build_features(docs):
    if not docs:
        return pd.DataFrame()

    # ✅ normalize + flatten important fields first
    docs = [normalize_doc_fields(d) for d in docs]
    docs = [extract_auth_fields(d) for d in docs]

    df = pd.DataFrame(docs)

    # Normalize timestamp
    if "timestamp" not in df.columns and "@timestamp" in df.columns:
        df["timestamp"] = df["@timestamp"]
    ensure_col(df, "timestamp", "")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Required columns
    ensure_col(df, "source_ip", "")
    ensure_col(df, "protocol", "unknown")
    ensure_col(df, "usernames_joined", "")
    ensure_col(df, "passwords_joined", "")
    ensure_col(df, "username", "")
    ensure_col(df, "password", "")

    df["username_effective"] = df["usernames_joined"]
    df.loc[df["username_effective"].str.strip() == "", "username_effective"] = df["username"]

    df["password_effective"] = df["passwords_joined"]
    df.loc[df["password_effective"].str.strip() == "", "password_effective"] = df["password"]

    df["cred_pair"] = df["username_effective"].str.strip() + ":" + df["password_effective"].str.strip()

    # Numeric fields (destination_port etc.)
    for col in ["duration", "destination_port", "num_auth_attempts", "auth_attempts_count"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # If duration was ECS nanoseconds, it can be huge—optional normalize to seconds:
    # (Uncomment if your durations look massive in debug)
    # df["duration"] = df["duration"] / 1e9

    if df["source_ip"].astype(str).str.strip().eq("").all():
        return pd.DataFrame()

    eps = 1e-6
    g = df.groupby("source_ip", dropna=True)

    if "session_id" in df.columns:
        session_count = g["session_id"].nunique()
    else:
        session_count = g.size()

    feat = pd.DataFrame({
        "source_ip": session_count.index,
        "session_count": session_count.values,
        "event_count": g.size().values,
        "total_duration": g["duration"].sum().values,
        "unique_ports": g["destination_port"].nunique().values,
        "unique_protocols": g["protocol"].nunique().values,
        "auth_event_count": g["auth_attempts_count"].sum().values,
        "unique_cred_pairs": g["cred_pair"].nunique().values,
    })

    feat["events_per_session"] = feat["event_count"] / (feat["session_count"] + eps)
    feat["auth_per_session"] = feat["auth_event_count"] / (feat["session_count"] + eps)
    feat["duration_per_session"] = feat["total_duration"] / (feat["session_count"] + eps)

    return feat


# ===========================
# OpenCTI helpers
# ===========================
def ensure_label(opencti, name, label_cache=None):
    if label_cache is None:
        label_cache = {}

    if name in label_cache:
        return label_cache[name]

    try:
        label = opencti.label.create(value=name, color="#ffaa00")
        if label and label.get("id"):
            label_cache[name] = label["id"]
            return label["id"]
    except Exception as e:
        print(f"Label creation failed for {name}, attempting lookup: {e}")

    try:
        result = opencti.label.list(
            filters={
                "mode": "and",
                "filters": [{
                    "key": "value",
                    "values": [name],
                    "operator": "eq"
                }],
                "filterGroups": []
            }
        )
        if result and len(result) > 0 and result[0].get("id"):
            label_cache[name] = result[0]["id"]
            return result[0]["id"]
    except Exception as e:
        print(f"Label lookup failed for {name}: {e}")

    print(f"WARNING: Could not create or find label {name}")
    return None


def ensure_threat_actor(opencti, actor_name):
    try:
        result = opencti.threat_actor_group.list(
            filters={
                "mode": "and",
                "filters": [{
                    "key": "name",
                    "values": [actor_name],
                    "operator": "eq"
                }],
                "filterGroups": []
            }
        )
        if result and len(result) > 0 and result[0].get("id"):
            return result[0]["id"]
    except Exception as e:
        print(f"Error searching for existing actor {actor_name}: {e}")

    try:
        actor = opencti.threat_actor_group.create(
            name=actor_name,
            description="Auto-created by honeypot ML profiler",
            confidence=50,
            update=True
        )
        if actor and isinstance(actor, dict) and actor.get("id"):
            return actor["id"]
    except Exception as e:
        print(f"Error creating actor {actor_name}: {e}")

    return None


def upsert_ip_indicator(opencti, ip, labels, label_cache=None, confidence=75):
    if label_cache is None:
        label_cache = {}

    if ":" in ip:
        pattern = f"[ipv6-addr:value = '{ip}']"
        name = f"IPv6 {ip}"
        observable_type = "IPv6-Addr"
    else:
        pattern = f"[ipv4-addr:value = '{ip}']"
        name = f"IPv4 {ip}"
        observable_type = "IPv4-Addr"

    indicator_id = None

    try:
        result = opencti.indicator.list(
            filters={
                "mode": "and",
                "filters": [{
                    "key": "pattern",
                    "values": [pattern],
                    "operator": "eq"
                }],
                "filterGroups": []
            }
        )
        if result and len(result) > 0 and result[0].get("id"):
            indicator_id = result[0]["id"]
    except Exception as e:
        print(f"Indicator lookup failed for {ip}: {e}")

    if not indicator_id:
        try:
            indicator = opencti.indicator.create(
                name=name,
                pattern_type="stix",
                pattern=pattern,
                x_opencti_main_observable_type=observable_type,
                confidence=confidence,
                update=True,
            )
            if indicator and isinstance(indicator, dict) and indicator.get("id"):
                indicator_id = indicator["id"]
        except Exception as e:
            print(f"Indicator creation failed for {ip}: {e}")

    if not indicator_id:
        print(f"ERROR: could not create or retrieve indicator for {ip}, skipping")
        return None

    for label_name in labels:
        try:
            label_id = ensure_label(opencti, label_name, label_cache)
            if label_id:
                opencti.stix_domain_object.add_label(id=indicator_id, label_id=label_id)
        except Exception as e:
            print(f"Label add failed for {label_name}: {e}")

    return indicator_id


def link_indicator_to_actor(opencti, indicator_id, actor_name):
    if not indicator_id:
        print(f"ERROR: Invalid indicator_id: {indicator_id}")
        return False

    actor_id = ensure_threat_actor(opencti, actor_name)
    if not actor_id:
        print(f"ERROR: Invalid actor_id for {actor_name}: {actor_id}")
        return False

    try:
        rel = opencti.stix_core_relationship.create(
            fromId=str(indicator_id),
            toId=str(actor_id),
            relationship_type="indicates",
            description="Auto-linked by honeypot profiler",
            confidence=70,
            update=True,
        )
        print(f"✓ Created indicates relationship: {rel.get('id') if isinstance(rel, dict) else rel}")
        return True
    except Exception as e:
        print(f"ERROR creating indicates relationship: {e}")
        print(f"  fromId (indicator): {repr(indicator_id)}")
        print(f"  toId (actor): {repr(actor_id)}")
        return False


# ===========================
# MAIN
# ===========================
def main():
    if not OPENCTI_TOKEN:
        raise RuntimeError("OPENCTI_TOKEN required")

    best_bundle, cluster_bundle = load_models_from_hf()

    model = best_bundle["model"]
    model_feature_cols = best_bundle["feature_cols"]

    cluster_model, cluster_feature_cols = _extract_model_and_cols(
        cluster_bundle,
        default_cols=model_feature_cols,
        bundle_name="cluster_bundle",
    )

    opencti = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
    es_url = ES_URL.rstrip("/")

    label_cache = {}

    while True:
        print("Fetching ALL historical logs...")
        docs = fetch_events(es_url, since_ts=None)

        feat = build_features(docs)
        if feat.empty:
            print("No features built")
            time.sleep(RUN_EVERY_SECONDS)
            continue

        # Ensure columns for both models
        for col in model_feature_cols:
            if col not in feat.columns:
                feat[col] = 0.0
        for col in cluster_feature_cols:
            if col not in feat.columns:
                feat[col] = 0.0

        X_df = feat[model_feature_cols].astype(float)
        pred = model.predict(X_df)

        C_df = feat[cluster_feature_cols].astype(float)
        cluster_ids = cluster_model.predict(C_df)

        # Debug (once per cycle)
        u_pred = np.unique(pred)
        u_cluster = np.unique(cluster_ids)
        print("Pred unique:", u_pred, "count:", len(u_pred))
        print("Cluster unique:", u_cluster, "count:", len(u_cluster))
        print("Feature variance (quick):")
        try:
            print(feat.drop(columns=["source_ip"]).var(numeric_only=True).sort_values(ascending=False).head(10))
        except Exception:
            pass

        # ✅ Fix: if clustering collapses, fall back to actor derived from pred (Option A)
        use_pred_as_actor = (len(u_cluster) <= 1)

        processed_ips = set()

        for ip, label, cid in zip(feat["source_ip"], pred, cluster_ids):
            if ip in processed_ips:
                continue
            processed_ips.add(ip)

            if use_pred_as_actor:
                actor_name = f"HP-ACTOR-{str(label)}"
            else:
                try:
                    actor_name = f"HP-ACTOR-{int(cid):03d}"
                except Exception:
                    actor_name = f"HP-ACTOR-{str(cid)}"

            print(f"\n--- Processing IP: {ip} (actor: {actor_name}, pred: {label}, cluster: {cid}) ---")

            labels = [
                "honeypot",
                "actor-profile",
                str(label),
                "hp-cluster",
                actor_name,
            ]

            indicator_id = upsert_ip_indicator(opencti, ip, labels, label_cache=label_cache)

            if indicator_id and isinstance(indicator_id, str) and len(indicator_id) > 0:
                link_indicator_to_actor(opencti, indicator_id, actor_name)
            else:
                print(f"✗ Invalid indicator_id, skipping relationship for {ip}")

        print(f"\n=== Cycle complete: processed {len(processed_ips)} unique IPs ===")
        time.sleep(RUN_EVERY_SECONDS)


if __name__ == "__main__":
    main()
