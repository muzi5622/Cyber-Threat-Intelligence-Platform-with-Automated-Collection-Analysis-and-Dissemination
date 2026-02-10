from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple
from collections import Counter, defaultdict
import re
import yaml

from .opencti_client import OpenCTIClient
from .scoring import compute_risk_score, decision_label


# ----------------------------
# Helpers
# ----------------------------

def load_cfg(cfg_path: str) -> Dict[str, Any]:
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


THEME_KEYWORDS: List[str] = [
    "ransomware", "phishing", "credential", "exploit", "zero-day", "c2",
    "botnet", "malware", "apt", "supply chain", "ddos",
]

THEME_INTERPRETATION: Dict[str, str] = {
    "exploit": "Accelerated exploitation of exposed services suggests attackers are prioritizing speed-to-access over bespoke tooling.",
    "zero-day": "Zero-day themes imply elevated uncertainty and higher potential impact due to limited mitigations early in the window.",
    "credential": "Credential-focused activity is a leading indicator for account takeover and lateral movement risk.",
    "phishing": "Phishing volume indicates identity systems and user workflows remain high-leverage attack paths.",
    "ransomware": "Ransomware signals imply disruptive intent and high business impact (availability/operations).",
    "apt": "APT themes suggest long-horizon activity and potential strategic targeting rather than opportunistic noise.",
    "supply chain": "Supply-chain themes imply indirect compromise paths with amplified blast radius across vendors and dependencies.",
    "c2": "C2 signals suggest sustained footholds and the need to validate egress controls and detection coverage.",
    "ddos": "DDoS activity tends to correlate with disruption intent and reputational impact, especially for online services.",
    "malware": "Malware volume usually indicates broad commodity activity; the risk depends on delivery vectors and controls maturity.",
    "botnet": "Botnet activity indicates scalable infrastructure abuse and opportunistic targeting of exposed services.",
}

THEME_TO_EXPOSURE: Dict[str, str] = {
    "phishing": "Identity & Access (email/user workflows)",
    "credential": "Identity & Access (accounts/privilege)",
    "exploit": "Internet-facing infrastructure (patching/WAF/IPS)",
    "zero-day": "Internet-facing infrastructure (rapid mitigation)",
    "ransomware": "Backup/Recovery & endpoint resilience",
    "apt": "Long-horizon intrusion risk (monitoring/hunting)",
    "supply chain": "Third-party & software supply chain",
    "c2": "Network egress controls & detection",
    "ddos": "Availability & online service resilience",
    "malware": "Endpoint controls & delivery vectors",
    "botnet": "Perimeter exposure & service hardening",
}


def theme_counts(texts: List[str]) -> Counter:
    c = Counter()
    for t in texts:
        lt = (t or "").lower()
        for k in THEME_KEYWORDS:
            if k in lt:
                c[k] += 1
    return c


def summarize_themes(texts: List[str], top_n: int = 10) -> List[Tuple[str, int]]:
    return theme_counts(texts).most_common(top_n)


def theme_trends(curr: Counter, prev: Counter, top_n: int = 6) -> Dict[str, List[Tuple[str, int]]]:
    keys = set(curr.keys()) | set(prev.keys())
    deltas = [(k, int(curr.get(k, 0) - prev.get(k, 0))) for k in keys]
    rising = sorted([x for x in deltas if x[1] > 0], key=lambda x: x[1], reverse=True)[:top_n]
    falling = sorted([x for x in deltas if x[1] < 0], key=lambda x: x[1])[:top_n]
    stable = sorted([x for x in deltas if x[1] == 0], key=lambda x: curr.get(x[0], 0), reverse=True)[:top_n]
    return {"rising": rising, "falling": falling, "stable": stable}


def risk_trajectory_label(curr_avg: float, prev_avg: float, curr_count: int, prev_count: int) -> Tuple[str, str]:
    """
    Returns (label, rationale). Labels: IMPROVING / STABLE / ELEVATED.
    Simple and explainable heuristic for executives.
    """
    prev_avg = prev_avg if prev_avg > 0 else 0.0
    prev_count = prev_count if prev_count > 0 else 0

    avg_delta = curr_avg - prev_avg
    count_delta = curr_count - prev_count

    if avg_delta >= 5 or (count_delta >= 30 and curr_avg >= prev_avg):
        return "ELEVATED (↑)", "Risk/volume increased vs previous period."
    if avg_delta <= -5 and count_delta <= 0:
        return "IMPROVING (↓)", "Risk decreased vs previous period."
    return "STABLE (→)", "No material change vs previous period."


_token_re = re.compile(r"[a-z0-9]{3,}", re.IGNORECASE)

def _bag(text: str) -> set[str]:
    toks = _token_re.findall((text or "").lower())
    stop = {
        "the","and","for","with","from","that","this","into","your","are","was","were",
        "has","have","not","but","new","using","used","over","under","via","its","their",
        "they","them","will","can","may",
        "attack","attacks","threat","threats","report","reports",
    }
    return {t for t in toks if t not in stop and len(t) >= 4}


def cluster_reports(texts: List[str], max_clusters: int = 3, sim_threshold: float = 0.22) -> List[Dict[str, Any]]:
    """
    Lightweight 'ML-like' clustering with no extra dependencies.
    Greedy Jaccard clustering over keyword bags.
    """
    bags = [_bag(t) for t in texts]
    clusters: List[Dict[str, Any]] = []

    def jacc(a: set[str], b: set[str]) -> float:
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0

    for i, bag_i in enumerate(bags):
        placed = False
        for c in clusters:
            if jacc(bag_i, c["centroid"]) >= sim_threshold:
                c["idx"].append(i)
                c["centroid"] = c["centroid"] | bag_i
                placed = True
                break
        if not placed:
            clusters.append({"idx": [i], "centroid": set(bag_i)})

    clusters.sort(key=lambda x: len(x["idx"]), reverse=True)
    kept = clusters[:max_clusters]
    rest = clusters[max_clusters:]

    if rest:
        other_idx = []
        other_centroid = set()
        for r in rest:
            other_idx.extend(r["idx"])
            other_centroid |= r["centroid"]
        kept.append({"idx": other_idx, "centroid": other_centroid})

    out = []
    for c in kept:
        kw = Counter()
        for t in c["centroid"]:
            kw[t] += 1
        top_kw = [k for k, _ in kw.most_common(6)]
        out.append({"count": len(c["idx"]), "keywords": top_kw})
    return out


def top_exposures(theme_counts_: Counter, top_n: int = 4) -> List[Tuple[str, int]]:
    exp_counts: Dict[str, int] = defaultdict(int)
    for theme, cnt in theme_counts_.items():
        exp = THEME_TO_EXPOSURE.get(theme)
        if exp:
            exp_counts[exp] += int(cnt)
    return sorted(exp_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]


def strategic_driver_bullets(top_themes: List[Tuple[str, int]], max_bullets: int = 4) -> List[str]:
    bullets = []
    for theme, _cnt in top_themes:
        msg = THEME_INTERPRETATION.get(theme)
        if msg and msg not in bullets:
            bullets.append(msg)
        if len(bullets) >= max_bullets:
            break
    if not bullets:
        bullets.append("No single theme dominated the period; maintain baseline monitoring and core hygiene controls.")
    return bullets


def leadership_actions_from_themes(top_themes: List[Tuple[str, int]]) -> List[str]:
    themes = {k for k, _ in top_themes}
    actions = []
    if "phishing" in themes or "credential" in themes:
        actions.append("Approve a focused identity hardening push: tighten DMARC, review MFA coverage for privileged roles, and expand conditional access policies.")
    if "exploit" in themes or "zero-day" in themes:
        actions.append("Authorize an emergency patch/mitigation playbook for internet-facing assets (patch SLAs, WAF/IPS virtual patching, exposure inventory).")
    if "ransomware" in themes:
        actions.append("Sponsor a ransomware readiness review: validate restore SLAs, test backups, and confirm endpoint protection coverage on critical systems.")
    if "supply chain" in themes:
        actions.append("Direct vendor risk review for key software/providers and prioritize SBOM/third-party patch visibility where possible.")
    if "ddos" in themes:
        actions.append("Validate DDoS resilience and run an availability tabletop exercise for critical online services.")
    if not actions:
        actions.append("Maintain baseline security hygiene and monitoring; no urgent strategic action triggered by this period’s themes.")
    return actions[:5]


# ----------------------------
# Reports
# ----------------------------

def build_daily_exec_summary(cfg_path: str) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg.get("org_profile", {})
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=1)

    reports_data = client.list_reports(iso(start), iso(now), first=300)
    edges = reports_data.get("reports", {}).get("edges", [])

    items = []
    texts = []
    for e in edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        items.append(
            {"id": n["id"], "name": n.get("name", "Report"), "created_at": n.get("created_at"), "risk": score["risk"], "decision": label}
        )
        texts.append((n.get("name") or "") + "\n" + (n.get("description") or ""))

    items.sort(key=lambda x: x["risk"], reverse=True)
    top_items = items[:8]
    themes = summarize_themes(texts, top_n=7)

    # Exec: show count; keep only a few IOCs in annex
    obs_data = client.list_observables(iso(start), iso(now), first=500)
    obs_edges = obs_data.get("stixCyberObservables", {}).get("edges", [])
    observables = [e["node"] for e in obs_edges]
    observables.sort(key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)
    top_obs = observables[:3]

    avg_risk = sum([x["risk"] for x in items]) / max(1, len(items))
    posture = "ELEVATED" if avg_risk >= 70 else ("ATTENTION" if avg_risk >= 55 else "BASELINE")

    body = []
    body.append(f"# Executive Daily Cyber Brief — {now.strftime('%Y-%m-%d')} ({org.get('name','Org')})")
    body.append("**Window:** last 24 hours (UTC)\n")

    body.append("## Executive Snapshot")
    body.append(f"- **Risk posture:** **{posture}** (Avg risk {avg_risk:.0f}/100)")
    body.append(f"- **Intel volume:** {len(items)} reports; {len(observables)} new observables")
    if themes:
        body.append(f"- **Primary drivers:** " + ", ".join([k for k, _ in themes[:3]]))
    body.append("")

    body.append("## Key Decisions (Auto-triage)")
    if not top_items:
        body.append("- No reports found in the last 24h.")
    else:
        for t in top_items:
            body.append(f"- **[{t['decision']}]** (Risk {t['risk']}/100) — {t['name']}")
    body.append("")

    body.append("## Leadership Actions")
    for a in leadership_actions_from_themes(themes):
        body.append(f"- {a}")
    body.append("")

    body.append("## Technical Annex (for SOC)")
    if themes:
        body.append("**Top themes:** " + ", ".join([f"{k} ({v})" for k, v in themes]))
    if top_obs:
        body.append("\n**Top observables (by score):**")
        for o in top_obs:
            val = o.get("observable_value", "")
            et = o.get("entity_type", "Observable")
            sc = o.get("x_opencti_score") or 0
            body.append(f"- {et} (Score {sc}) — `{val}`")

    return {
        "report_name": f"Executive Daily Cyber Brief — {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": top_items,
    }


def build_weekly_brief(cfg_path: str) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg.get("org_profile", {})
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)

    prev_start = start - timedelta(days=7)
    prev_end = start

    curr_reports = client.list_reports(iso(start), iso(now), first=800)
    curr_edges = curr_reports.get("reports", {}).get("edges", [])
    curr_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in curr_edges]

    prev_reports = client.list_reports(iso(prev_start), iso(prev_end), first=800)
    prev_edges = prev_reports.get("reports", {}).get("edges", [])
    prev_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in prev_edges]

    scored = []
    curr_risks = []
    for e in curr_edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        scored.append({"id": n["id"], "name": n.get("name"), "risk": score["risk"], "decision": label})
        curr_risks.append(score["risk"])
    scored.sort(key=lambda x: x["risk"], reverse=True)

    curr_avg = sum(curr_risks) / max(1, len(curr_risks))
    prev_risks = [compute_risk_score(e["node"], org, cfg)["risk"] for e in prev_edges]
    prev_avg = (sum(prev_risks) / len(prev_risks)) if prev_risks else 0.0

    posture, posture_reason = risk_trajectory_label(curr_avg, prev_avg, len(curr_edges), len(prev_edges))
    themes = summarize_themes(curr_texts, top_n=10)
    trends = theme_trends(theme_counts(curr_texts), theme_counts(prev_texts), top_n=5)

    body = []
    body.append(f"# Executive Weekly Cyber Risk Brief — Week ending {now.strftime('%Y-%m-%d')} ({org.get('name','Org')})")
    body.append("**Window:** last 7 days (UTC)\n")

    body.append("## Executive Snapshot")
    body.append(f"- **Risk trajectory:** **{posture}** — {posture_reason}")
    body.append(f"- **Intel volume:** {len(curr_edges)} reports (prev {len(prev_edges)})")
    if themes:
        body.append(f"- **Primary drivers:** " + ", ".join([k for k, _ in themes[:3]]))
    body.append("")

    body.append("## Strategic Drivers")
    for b in strategic_driver_bullets(themes, max_bullets=4):
        body.append(f"- {b}")
    body.append("")

    body.append("## Trend Signals (Week-over-Week)")
    if trends["rising"]:
        body.append("**Rising themes:**")
        for k, d in trends["rising"]:
            body.append(f"- {k}: +{d}")
    else:
        body.append("- No rising themes detected vs last week.")
    if trends["falling"]:
        body.append("\n**Falling themes:**")
        for k, d in trends["falling"]:
            body.append(f"- {k}: {d}")
    body.append("")

    body.append("## Business Exposure Assessment")
    exp = top_exposures(theme_counts(curr_texts), top_n=4)
    if exp:
        for k, v in exp:
            body.append(f"- **{k}** — signal strength {v}")
    else:
        body.append("- No dominant exposure areas detected.")
    body.append("")

    body.append("## Top Strategic Risks (Auto-triage)")
    for x in scored[:8]:
        body.append(f"- **[{x['decision']}]** (Risk {x['risk']}/100) — {x['name']}")
    body.append("")

    body.append("## Leadership Actions")
    for a in leadership_actions_from_themes(themes):
        body.append(f"- {a}")

    return {
        "report_name": f"Executive Weekly Cyber Risk Brief — Week ending {now.strftime('%Y-%m-%d')}",
        "description": "\n".join(body),
        "top_items": scored[:10],
    }


def build_monthly_landscape(cfg_path: str, days: int = 30) -> Dict[str, Any]:
    cfg = load_cfg(cfg_path)
    org = cfg.get("org_profile", {})
    client = OpenCTIClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    prev_start = start - timedelta(days=days)
    prev_end = start

    curr_reports = client.list_reports(iso(start), iso(now), first=1200)
    curr_edges = curr_reports.get("reports", {}).get("edges", [])
    curr_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in curr_edges]

    prev_reports = client.list_reports(iso(prev_start), iso(prev_end), first=1200)
    prev_edges = prev_reports.get("reports", {}).get("edges", [])
    prev_texts = [((e["node"].get("name") or "") + "\n" + (e["node"].get("description") or "")) for e in prev_edges]

    scored = []
    curr_risks = []
    for e in curr_edges:
        n = e["node"]
        score = compute_risk_score(n, org, cfg)
        label = decision_label(score["risk"], cfg)
        scored.append({"id": n["id"], "name": n.get("name"), "risk": score["risk"], "decision": label})
        curr_risks.append(score["risk"])
    scored.sort(key=lambda x: x["risk"], reverse=True)

    prev_risks = [compute_risk_score(e["node"], org, cfg)["risk"] for e in prev_edges]
    curr_avg = sum(curr_risks) / max(1, len(curr_risks))
    prev_avg = (sum(prev_risks) / len(prev_risks)) if prev_risks else 0.0

    posture, posture_reason = risk_trajectory_label(curr_avg, prev_avg, len(curr_edges), len(prev_edges))

    curr_counts = theme_counts(curr_texts)
    prev_counts = theme_counts(prev_texts)
    top_themes = curr_counts.most_common(8)
    trends = theme_trends(curr_counts, prev_counts, top_n=6)
    exposures = top_exposures(curr_counts, top_n=4)

    obs_data = client.list_observables(iso(start), iso(now), first=2000)
    obs_edges = obs_data.get("stixCyberObservables", {}).get("edges", [])
    observables = [e["node"] for e in obs_edges]
    observables.sort(key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)
    top_obs = observables[:10]

    clusters = cluster_reports(curr_texts, max_clusters=3)

    outlook = []
    themes_set = {k for k, _ in top_themes}
    if "exploit" in themes_set or "zero-day" in themes_set:
        outlook.append("Continued exploitation of public-facing services is likely; maintain rapid mitigation pathways and validate exposure inventories.")
    if "credential" in themes_set or "phishing" in themes_set:
        outlook.append("Credential abuse will remain a leading access vector; focus on identity hardening and user workflow protections.")
    if "ransomware" in themes_set:
        outlook.append("Opportunistic ransomware attempts remain plausible; validate backups and enforce segmentation/EDR coverage for critical assets.")
    if "supply chain" in themes_set:
        outlook.append("Third-party software risk may increase; prioritize vendor patch visibility and review high-trust integrations.")
    if not outlook:
        outlook.append("No dominant forward signal emerged; expect a mixed landscape with continued commodity activity.")

    body = []
    body.append(f"# Executive Cyber Risk Assessment — {now.strftime('%B %Y')} ({org.get('name','Org')})")
    body.append(f"**Assessment window:** last {days} days (UTC)\n")

    body.append("## Executive Snapshot")
    body.append(f"- **Risk trajectory:** **{posture}** — {posture_reason}")
    body.append(f"- **Average risk score:** {curr_avg:.0f}/100 (prev {prev_avg:.0f}/100)")
    body.append(f"- **Intel volume:** {len(curr_edges)} reports (prev {len(prev_edges)}); {len(observables)} observables created")
    if top_themes:
        body.append(f"- **Primary drivers:** " + ", ".join([k for k, _ in top_themes[:3]]))
    body.append("")

    body.append("## Strategic Drivers (Why this matters)")
    for b in strategic_driver_bullets(top_themes, max_bullets=4):
        body.append(f"- {b}")
    body.append("")

    body.append("## Business Exposure Assessment (So what)")
    if exposures:
        for k, v in exposures:
            body.append(f"- **{k}** — signal strength {v}")
    else:
        body.append("- No dominant exposure areas detected.")
    body.append("")

    body.append("## Trend Signals (Period-over-Period)")
    if trends["rising"]:
        body.append("**Rising themes:**")
        for k, d in trends["rising"]:
            body.append(f"- {k}: +{d}")
    else:
        body.append("- No rising themes vs previous period.")
    if trends["falling"]:
        body.append("\n**Falling themes:**")
        for k, d in trends["falling"]:
            body.append(f"- {k}: {d}")
    body.append("")

    body.append("## Dominant Activity Clusters (Noise reduced)")
    if clusters:
        for i, c in enumerate(clusters[:4], start=1):
            kws = ", ".join(c["keywords"][:6]) if c["keywords"] else "mixed indicators"
            body.append(f"- **Cluster {i}**: {c['count']} related reports — likely themes: {kws}")
    else:
        body.append("- Clustering unavailable (insufficient text).")
    body.append("")

    body.append("## Leadership Actions (Decisions)")
    for a in leadership_actions_from_themes(top_themes):
        body.append(f"- {a}")
    body.append("")

    body.append("## Forward Outlook (Next 30–60 days)")
    for o in outlook[:4]:
        body.append(f"- {o}")
    body.append("")

    body.append("---")
    body.append("## Technical Annex (SOC / Engineering)")
    body.append("### Top Strategic Risks (Auto-triage)")
    for x in scored[:10]:
        body.append(f"- **[{x['decision']}]** (Risk {x['risk']}/100) — {x['name']}")
    body.append("")
    body.append("### Top Observables (by score)")
    if not top_obs:
        body.append("- No observables in this period.")
    else:
        for o in top_obs:
            val = o.get("observable_value", "")
            et = o.get("entity_type", "Observable")
            sc = o.get("x_opencti_score") or 0
            body.append(f"- {et} (Score {sc}) — `{val}`")

    return {
        "report_name": f"Executive Cyber Risk Assessment — {now.strftime('%B %Y')}",
        "description": "\n".join(body),
        "top_items": scored[:10],
    }
 
