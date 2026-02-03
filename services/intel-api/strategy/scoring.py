from datetime import datetime, timezone
from typing import Dict, Any
from collections import Counter


def _days_old(created_at_iso: str) -> float:
    dt = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def compute_relevance(text: str, org_profile: Dict[str, Any]) -> int:
    if not text:
        return 0
    t = text.lower()
    hits = 0

    for k in org_profile.get("sector_keywords", []):
        if k.lower() in t:
            hits += 2
    for k in org_profile.get("geo_keywords", []):
        if k.lower() in t:
            hits += 2
    for k in org_profile.get("tech_keywords", []):
        if k.lower() in t:
            hits += 1

    return min(25, hits * 3)


def compute_severity(text: str, cfg: Dict[str, Any]) -> int:
    base = int(cfg["scoring"].get("base_severity", 10))
    boosts = cfg["scoring"].get("severity_keywords", {})
    if not text:
        return base

    t = text.lower()
    score = base
    for kw, pts in boosts.items():
        if kw.lower() in t:
            score += int(pts)
    return min(50, score)


def compute_recency_points(created_at_iso: str, cfg: Dict[str, Any]) -> int:
    rec = cfg["scoring"].get("recency", {})
    max_days = float(rec.get("max_days", 14))
    max_points = float(rec.get("max_points", 25))

    d = _days_old(created_at_iso)
    if d >= max_days:
        return 0
    return int(round(max_points * (1.0 - d / max_days)))


def normalize_confidence(conf: Any) -> int:
    try:
        c = int(conf) if conf is not None else 50
    except Exception:
        c = 50
    return max(0, min(100, c))


def normalize_source_reliability() -> int:
    return 60  # constant baseline for now


def decision_label(risk: int, cfg: Dict[str, Any]) -> str:
    d = cfg["decisions"]
    if risk >= int(d["block_now"]):
        return "BLOCK"
    if risk >= int(d["monitor"]):
        return "MONITOR"
    return "IGNORE"


def compute_risk_score(item: Dict[str, Any], org_profile: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    weights = cfg["scoring"]["weights"]
    text = (item.get("name") or "") + "\n" + (item.get("description") or "")
    created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()

    src = normalize_source_reliability()
    conf = normalize_confidence(item.get("confidence"))
    sev = compute_severity(text, cfg)
    rel = compute_relevance(text, org_profile)
    rec = compute_recency_points(created_at, cfg)

    score = (
        weights["source_reliability"] * src
        + weights["confidence"] * conf
        + weights["severity"] * (sev * 2)
        + weights["relevance"] * (rel * 4)
        + weights["recency"] * (rec * 4)
    )

    final = int(round(max(0, min(100, score))))
    return {
        "risk": final,
        "components": {"source": src, "confidence": conf, "severity": sev, "relevance": rel, "recency": rec},
    }
 
