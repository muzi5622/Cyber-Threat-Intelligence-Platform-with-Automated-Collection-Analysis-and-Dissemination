import os
import time
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta

import requests
import feedparser
from dateutil import parser as dtparser


# -------------------------
# Config
# -------------------------
OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "300"))

FEEDS_FILE = os.getenv("FEEDS_FILE", "/app/feeds.txt")

MAX_ITEMS_PER_FEED = int(os.getenv("MAX_ITEMS_PER_FEED", "5"))   # create up to N reports per feed
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "30"))            # accept items within last N days
DISABLE_DEDUP = os.getenv("DISABLE_DEDUP", "false").lower() in ("1", "true", "yes")

STATE_DB = os.getenv("RSS_STATE_DB", "/state/rss.db")            # sqlite state
PRODUCER_NAME = os.getenv("RSS_PRODUCER_NAME", "RSS Feed Ingestor")
PRODUCER_DESC = os.getenv("RSS_PRODUCER_DESC", "Automated OSINT collection from CTI RSS sources.")

DEFAULT_CONFIDENCE = int(os.getenv("RSS_CONFIDENCE", "50"))

GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}


# -------------------------
# GraphQL helper
# -------------------------
def gql(query: str, variables=None):
    r = requests.post(GQL, headers=HEADERS, json={"query": query, "variables": variables or {}}, timeout=60)
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]


# -------------------------
# State DB
# -------------------------
def state_init():
    os.makedirs(os.path.dirname(STATE_DB), exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS seen (
        id TEXT PRIMARY KEY,
        seen_at TEXT NOT NULL
      )
    """)
    conn.commit()
    return conn


def seen_has(conn, key: str) -> bool:
    if DISABLE_DEDUP:
        return False
    cur = conn.execute("SELECT 1 FROM seen WHERE id = ?", (key,))
    return cur.fetchone() is not None


def seen_put(conn, key: str):
    if DISABLE_DEDUP:
        return
    conn.execute("INSERT OR REPLACE INTO seen (id, seen_at) VALUES (?, ?)",
                 (key, datetime.now(timezone.utc).isoformat()))
    conn.commit()


def stable_key(feed_url: str, entry) -> str:
    # Use feed url + id/link/title to create stable dedup key
    raw = feed_url + "||" + (getattr(entry, "id", "") or "") + "||" + (getattr(entry, "link", "") or "") + "||" + (getattr(entry, "title", "") or "")
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


# -------------------------
# Utilities
# -------------------------
def load_feeds():
    with open(FEEDS_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines()]
    # drop empty and comments
    return [ln for ln in lines if ln and not ln.startswith("#")]


def parse_published(entry) -> datetime:
    # Try common RSS fields, fallback to now()
    candidates = []
    for k in ("published", "updated", "created"):
        v = getattr(entry, k, None)
        if v:
            candidates.append(v)
    # feedparser sometimes has published_parsed (time.struct_time)
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except Exception:
            pass

    for v in candidates:
        try:
            dt = dtparser.parse(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            continue

    return datetime.now(timezone.utc)


def within_lookback(dt: datetime) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    return dt >= cutoff


def clean_text(s: str) -> str:
    return (s or "").strip()


# -------------------------
# OpenCTI: Identity (createdBy)
# -------------------------
def ensure_identity(name: str, description: str) -> str:
    # Create or fetch an identity (Organization)
    q_find = """
    query FindIdentity($search: String!) {
      identities(search: $search, first: 1) { edges { node { id name } } }
    }
    """
    d = gql(q_find, {"search": name})
    edges = d.get("identities", {}).get("edges", [])
    if edges:
        return edges[0]["node"]["id"]

    q_create = """
    mutation CreateIdentity($input: IdentityAddInput!) {
      identityAdd(input: $input) { id name }
    }
    """
    # OpenCTI IdentityAddInput supports: type, name, description (type = Organization)
    d2 = gql(q_create, {"input": {"type": "Organization", "name": name, "description": description}})
    return (d2["identityAdd"]["id"])


# -------------------------
# OpenCTI: External Reference
# -------------------------
def external_reference_add(url: str, source_name: str, description: str) -> str:
    q = """
    mutation ExtRef($input: ExternalReferenceAddInput!) {
      externalReferenceAdd(input: $input) { id }
    }
    """
    inp = {"source_name": source_name, "url": url}
    if description:
        inp["description"] = description
    return gql(q, {"input": inp})["externalReferenceAdd"]["id"]


# -------------------------
# OpenCTI: Report
# -------------------------
def report_add(name: str, description: str, published_dt: datetime, created_by: str, ext_ref_ids):
    # Important: published must be full DateTime ISO string
    published = published_dt.isoformat().replace("+00:00", "Z")

    q = """
    mutation AddReport($input: ReportAddInput!) {
      reportAdd(input: $input) { id name }
    }
    """
    inp = {
        "name": name,
        "description": description,
        "published": published,
        "confidence": DEFAULT_CONFIDENCE,
        "report_types": ["threat-report"],
    }
    if created_by:
        inp["createdBy"] = created_by
    if ext_ref_ids:
        inp["externalReferences"] = ext_ref_ids

    return gql(q, {"input": inp})["reportAdd"]["id"]


# -------------------------
# Main ingestion
# -------------------------
def ingest_once():
    feeds = load_feeds()
    if not feeds:
        print("[rss-ingestor] feeds.txt empty", flush=True)
        return

    conn = state_init()

    # Health check (optional)
    try:
        gql("query { about { version } }")
    except Exception as e:
        print("[rss-ingestor] OpenCTI not ready:", e, flush=True)
        return

    created_by_id = ensure_identity(PRODUCER_NAME, PRODUCER_DESC)
    print(f"[rss-ingestor] loaded {len(feeds)} feeds | lookback={LOOKBACK_DAYS}d | max_items_per_feed={MAX_ITEMS_PER_FEED}", flush=True)

    total_created = 0

    for feed_url in feeds:
        try:
            parsed = feedparser.parse(feed_url)
            entries = getattr(parsed, "entries", []) or []
            if not entries:
                print(f"[rss-ingestor] feed has 0 entries: {feed_url}", flush=True)
                continue

            created_for_feed = 0

            # Most recent first
            for entry in entries[: 50]:
                if created_for_feed >= MAX_ITEMS_PER_FEED:
                    break

                title = clean_text(getattr(entry, "title", "")) or "Untitled CTI item"
                link = clean_text(getattr(entry, "link", ""))
                summary = clean_text(getattr(entry, "summary", "")) or clean_text(getattr(entry, "description", ""))

                pub_dt = parse_published(entry)
                if not within_lookback(pub_dt):
                    continue

                key = stable_key(feed_url, entry)
                if seen_has(conn, key):
                    continue

                # Build an external reference back to the article
                ext_ids = []
                if link:
                    try:
                        ext_ids.append(external_reference_add(
                            url=link,
                            source_name="rss",
                            description=f"Source feed: {feed_url}"
                        ))
                    except Exception as e:
                        print("[rss-ingestor] extref failed:", e, flush=True)

                # Create report
                try:
                    rid = report_add(
                        name=title,
                        description=(summary[:4000] if summary else f"Imported from feed: {feed_url}"),
                        published_dt=pub_dt,
                        created_by=created_by_id,
                        ext_ref_ids=ext_ids
                    )
                    seen_put(conn, key)
                    created_for_feed += 1
                    total_created += 1
                    print(f"[rss-ingestor] +report ({created_for_feed}/{MAX_ITEMS_PER_FEED}) {title[:90]}", flush=True)
                except Exception as e:
                    print("[rss-ingestor] reportAdd failed:", e, flush=True)

            print(f"[rss-ingestor] feed done: {feed_url} | created={created_for_feed}", flush=True)

        except Exception as e:
            print(f"[rss-ingestor] feed error {feed_url}: {e}", flush=True)

    print(f"[rss-ingestor] ingest_once complete | created_total={total_created}", flush=True)


def main_loop():
    print("[rss-ingestor] started", flush=True)
    while True:
        try:
            ingest_once()
        except Exception as e:
            print("[rss-ingestor] error:", e, flush=True)
        time.sleep(RUN_EVERY)


if __name__ == "__main__":
    if not OPENCTI_TOKEN:
        raise RuntimeError("OPENCTI_TOKEN is empty. Set OPENCTI_TOKEN env var.")
    main_loop()
 
