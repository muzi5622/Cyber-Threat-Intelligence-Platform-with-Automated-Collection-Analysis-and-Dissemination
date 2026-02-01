import os
import requests
from fastapi import FastAPI

OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}

app = FastAPI(title="CTI Intelligence API", version="1.0")

def gql(query, variables=None):
    r = requests.post(GQL, headers=HEADERS, json={"query": query, "variables": variables or {}}, timeout=30)
    r.raise_for_status()
    data = r.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

@app.get("/briefing")
def briefing():
    q = """
    query Briefing($n: Int!) {
      reports(first: $n, orderBy: created_at, orderMode: desc) {
        edges { node { id name description created_at } }
      }
      stixCyberObservables(first: $n, orderBy: created_at, orderMode: desc) {
        edges { node { id observable_value x_opencti_score created_at } }
      }
    }
    """
    d = gql(q, {"n": 10})
    reports = [e["node"] for e in d["reports"]["edges"]]
    iocs = [e["node"] for e in d["stixCyberObservables"]["edges"]]

    # Simple strategic “talk track”
    top_iocs = sorted(iocs, key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)[:5]
    return {
        "executive_summary": {
            "threat_landscape": f"{len(reports)} recent reports ingested; {len(iocs)} recent observables tracked.",
            "top_priority_iocs": top_iocs,
            "recommended_actions": [
                "Block top domains/IPs at perimeter controls",
                "Hunt for top hashes across EDR",
                "Patch any referenced CVEs with high business exposure",
            ],
        },
        "recent_reports": reports,
    }

@app.get("/roi")
def roi():
    # Demo ROI model: value = (#high confidence IOCs * 5) - (ops cost score)
    q = """
    query Roi($n: Int!) {
      stixCyberObservables(first: $n, orderBy: created_at, orderMode: desc) {
        edges { node { id x_opencti_score } }
      }
    }
    """
    d = gql(q, {"n": 200})
    scores = [(e["node"].get("x_opencti_score") or 0) for e in d["stixCyberObservables"]["edges"]]
    high = sum(1 for s in scores if s >= 70)
    ops_cost = 50  # fixed demo cost-unit
    value = (high * 5) - ops_cost
    return {
        "metrics": {
            "recent_observables": len(scores),
            "high_confidence_observables": high,
            "estimated_value_units": value
        },
        "roi_explanation": "Demo ROI = (high_confidence_IOCs * 5) - ops_cost_units"
    }
