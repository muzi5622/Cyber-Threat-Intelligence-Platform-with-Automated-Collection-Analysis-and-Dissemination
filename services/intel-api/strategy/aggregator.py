from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple
from collections import Counter
import os
import yaml

from .opencti_client import OpenCTIClient
from .scoring import compute_risk_score, decision_label


def load_cfg(cfg_path: str) -> Dict[str, Any]:
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def summarize_themes(texts: List[str]) -> List[Tuple[str, int]]:
    keywords = [
        "ransomware", "phishing", "credential", "exploit", "zero-day", "c2",
        "botnet", "malware", "apt", "supply chain", "ddos",
    ]
    c = Counter()
    for t in texts:
        lt = (t or "").lower()
        for k in keywords:
            if k in lt:
                c[k] += 1
    return c.most_common(7)


# ---------- NEW ADDITIONS ----------

def theme_counts(texts: List[str]) -> Counter:
    keywords = [
        "ransomware", "phishing", "credential", "exploit", "zero-day", "c2",
        "botnet", "malware", "apt", "supply chain", "ddos",
    ]
    c = Counter()
    for t in texts:
        lt = (t or "").lower()
        for k in keywords:
            if k in lt:
                c[k] += 1
    return c


def theme_trends(curr: Counter, prev: Counter, top_n: int = 5) -> Dict[str, List[Tuple[str, int]]]:
    all_keys = set(curr.keys()) | set(prev.keys())
    deltas = [(k, int(curr.get(k, 0) - prev.get(k, 0))) for k in all_keys]
    rising = sorted([x for x in deltas if x[1] > 0], key=lambda x: x[1], reverse=True)[:top_n]
    falling = sorted([x for x in deltas if x[1] < 0], key=lambda x: x[1])[:top_n]
    return {"rising": rising, "falling": falling}


# ---------- DAILY SUMMARY ----------

def build_daily_exec_summary(cfg_path: str) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg["org_profile"]
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=1)

    reports_data = client.list_reports(iso(start), iso(now), first=200)
    edges = reports_data.get("reports", {}).get("edges", [])

    # Observables
    obs_data = client.list_observables(iso(start), iso(now), first=300)
    obs_edges = obs_data.get("stixCyberObservables", {}).get("edges", [])
    observables = [e["node"] for e in obs_edges]
    observables.sort(key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)
    top_obs = observables[:5]

    items = []
    texts = []

    for e in edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        items.append(
            {
                "id": n["id"],
                "name": n.get("name", "Report"),
                "created_at": n.get("created_at"),
                "risk": score["risk"],
                "decision": label,
                "components": score["components"],
            }
        )
        texts.append((n.get("name") or "") + "\n" + (n.get("description") or ""))

    items.sort(key=lambda x: x["risk"], reverse=True)
    top = items[:10]
    themes = summarize_themes(texts)

    body = []
    body.append(f"# Daily Executive Summary ({org.get('name','Org')})")
    body.append(f"**Window:** last 24 hours (UTC)\n")
    body.append(f"**Reports ingested:** {len(items)}\n")

    if themes:
        body.append("## Top Threat Themes")
        for k, v in themes:
            body.append(f"- **{k}**: {v} mentions")
        body.append("")

    body.append("## Top Priority Items (Auto-triage)")
    if not top:
        body.append("- No reports found in the last 24h.")
    else:
        for t in top:
            body.append(f"- **[{t['decision']}]** (Risk {t['risk']}/100) — {t['name']}")
    body.append("")

    body.append("## Top Observables (24h)")
    if not top_obs:
        body.append("- No observables created in the last 24h.")
    else:
        for o in top_obs:
            val = o.get("observable_value", "")
            et = o.get("entity_type", "Observable")
            sc = o.get("x_opencti_score") or 0
            body.append(f"- **{et}** (Score {sc}) — `{val}`")
    body.append("")

    body.append("## Strategic Recommendations (Auto)")
    theme_names = [k for k, _ in themes]
    recs = []
    if "phishing" in theme_names or "credential" in theme_names:
        recs.append("Tighten email security (SPF/DKIM/DMARC), review phishing training, and enhance URL filtering.")
    if "ransomware" in theme_names:
        recs.append("Validate backup restores, enforce least privilege, and confirm EDR policies on critical assets.")
    if "exploit" in theme_names or "zero-day" in theme_names:
        recs.append("Prioritize patching for internet-facing assets and confirm WAF/IPS coverage.")
    if not recs:
        recs.append("No dominant theme detected today — maintain baseline monitoring and hygiene controls.")

    for r in recs[:5]:
        body.append(f"- {r}")

    return {
        "report_name": f"Daily Executive Summary — {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": top,
    }


# ---------- WEEKLY BRIEF ----------

def build_weekly_brief(cfg_path: str) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg["org_profile"]
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)

    reports_data = client.list_reports(iso(start), iso(now), first=500)
    edges = reports_data.get("reports", {}).get("edges", [])
    texts = []
    scored = []

    for e in edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        scored.append({"id": n["id"], "name": n.get("name"), "risk": score["risk"], "decision": label})
        texts.append((n.get("name") or "") + "\n" + (n.get("description") or ""))

    # Previous week
    prev_start = start - timedelta(days=7)
    prev_end = start
    prev_data = client.list_reports(iso(prev_start), iso(prev_end), first=500)
    prev_edges = prev_data.get("reports", {}).get("edges", [])
    prev_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in prev_edges]

    curr_counts = theme_counts(texts)
    prev_counts = theme_counts(prev_texts)
    trends = theme_trends(curr_counts, prev_counts, top_n=5)

    scored.sort(key=lambda x: x["risk"], reverse=True)
    themes = summarize_themes(texts)

    body = []
    body.append(f"# Weekly Strategic Risk Brief ({org.get('name','Org')})")
    body.append(f"**Window:** last 7 days (UTC)\n")
    body.append(f"**Reports ingested:** {len(scored)}\n")

    body.append("## Top Themes (7 days)")
    for k, v in themes:
        body.append(f"- **{k}**: {v} mentions")
    body.append("")

    body.append("## Trend Signals (Week-over-Week)")
    if trends["rising"]:
        body.append("**Rising themes:**")
        for k, dlt in trends["rising"]:
            body.append(f"- **{k}**: +{dlt}")
    else:
        body.append("- No rising themes detected vs last week.")

    if trends["falling"]:
        body.append("\n**Falling themes:**")
        for k, dlt in trends["falling"]:
            body.append(f"- **{k}**: {dlt}")
    body.append("")

    body.append("## Top 10 Highest-Risk Items")
    for x in scored[:10]:
        body.append(f"- **[{x['decision']}]** (Risk {x['risk']}/100) — {x['name']}")

    return {
        "report_name": f"Weekly Strategic Risk Brief — Week ending {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": scored[:10],
    }


# ---------- MONTHLY LANDSCAPE ----------

def build_monthly_landscape(cfg_path: str, days: int = 30) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg["org_profile"]
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    prev_start = start - timedelta(days=days)
    prev_end = start

    curr_reports = client.list_reports(iso(start), iso(now), first=800)
    curr_edges = curr_reports.get("reports", {}).get("edges", [])
    curr_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in curr_edges]

    prev_reports = client.list_reports(iso(prev_start), iso(prev_end), first=800)
    prev_edges = prev_reports.get("reports", {}).get("edges", [])
    prev_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in prev_edges]

    scored = []
    for e in curr_edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        scored.append({"id": n["id"], "name": n.get("name"), "risk": score["risk"], "decision": label})
    scored.sort(key=lambda x: x["risk"], reverse=True)

    curr_counts = theme_counts(curr_texts)
    prev_counts = theme_counts(prev_texts)
    trends = theme_trends(curr_counts, prev_counts, top_n=7)
    top_themes = curr_counts.most_common(10)

    obs_data = client.list_observables(iso(start), iso(now), first=1000)
    obs_edges = obs_data.get("stixCyberObservables", {}).get("edges", [])
    observables = [e["node"] for e in obs_edges]
    observables.sort(key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)
    top_obs = observables[:10]

    body = []
    body.append(f"# Monthly Threat Landscape & Trends ({org.get('name','Org')})")
    body.append(f"**Window:** last {days} days (UTC)\n")
    body.append(f"**Reports ingested:** {len(curr_edges)}")
    body.append(f"**Observables created:** {len(observables)}\n")

    body.append("## Top Threat Themes")
    for k, v in top_themes:
        body.append(f"- **{k}**: {v} mentions")
    body.append("")

    body.append("## Trend Signals (Period-over-Period)")
    for k, dlt in trends["rising"]:
        body.append(f"- **{k}**: +{dlt}")
    for k, dlt in trends["falling"]:
        body.append(f"- **{k}**: {dlt}")
    body.append("")

    body.append("## Top Strategic Risks (Auto-triage)")
    for x in scored[:10]:
        body.append(f"- **[{x['decision']}]** (Risk {x['risk']}/100) — {x['name']}")
    body.append("")

    body.append("## Top Observables (by score)")
    for o in top_obs:
        val = o.get("observable_value", "")
        et = o.get("entity_type", "Observable")
        sc = o.get("x_opencti_score") or 0
        body.append(f"- **{et}** (Score {sc}) — `{val}`")

    return {
        "report_name": f"Monthly Threat Landscape & Trends — {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": scored[:10],
    }
 
