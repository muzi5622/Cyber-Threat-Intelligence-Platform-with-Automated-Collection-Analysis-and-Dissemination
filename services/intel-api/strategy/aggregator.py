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


def build_daily_exec_summary(cfg_path: str) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg["org_profile"]
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=1)

    reports_data = client.list_reports(iso(start), iso(now), first=200)
    edges = reports_data.get("reports", {}).get("edges", [])

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

    scored.sort(key=lambda x: x["risk"], reverse=True)
    themes = summarize_themes(texts)

    high = [x for x in scored if x["risk"] >= 80]
    med = [x for x in scored if 60 <= x["risk"] < 80]

    body = []
    body.append(f"# Weekly Strategic Risk Brief ({org.get('name','Org')})")
    body.append(f"**Window:** last 7 days (UTC)\n")
    body.append(f"**Reports ingested:** {len(scored)}")
    body.append(f"**High risk items:** {len(high)}")
    body.append(f"**Medium risk items:** {len(med)}\n")

    body.append("## Top Themes (7 days)")
    if themes:
        for k, v in themes:
            body.append(f"- **{k}**: {v} mentions")
    else:
        body.append("- No dominant themes detected.")
    body.append("")

    body.append("## Top 10 Highest-Risk Items")
    for x in scored[:10]:
        body.append(f"- **[{x['decision']}]** (Risk {x['risk']}/100) — {x['name']}")
    body.append("")

    body.append("## Leadership Actions (Auto-proposed)")
    theme_names = [k for k, _ in themes]
    actions = []
    if "phishing" in theme_names or "credential" in theme_names:
        actions.append("Approve email gateway policy updates + enforce stronger DMARC posture on key domains.")
    if "ransomware" in theme_names:
        actions.append("Approve a ransomware tabletop exercise + validate restore SLAs for critical services.")
    if "exploit" in theme_names or "zero-day" in theme_names:
        actions.append("Approve emergency patch window policy for internet-facing assets.")
    if not actions:
        actions.append("No major new action recommended beyond standard monitoring and hygiene.")

    for a in actions[:5]:
        body.append(f"- {a}")

    return {
        "report_name": f"Weekly Strategic Risk Brief — Week ending {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": scored[:10],
    }
 
