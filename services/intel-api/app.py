import os
import requests
from fastapi import FastAPI, APIRouter, HTTPException

# Make local package imports always work
import sys
sys.path.append(os.path.dirname(__file__))

from strategy.scheduler import start_scheduler, run_daily, run_weekly, run_monthly

OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
GQL = f"{OPENCTI_BASE}/graphql"
HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"}

app = FastAPI(title="CTI Intelligence API", version="1.2")


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
        edges { node { id name description created_at confidence } }
      }
      stixCyberObservables(first: $n, orderBy: created_at, orderMode: desc) {
        edges { node { id observable_value x_opencti_score created_at entity_type } }
      }
    }
    """
    d = gql(q, {"n": 10})
    reports = [e["node"] for e in d["reports"]["edges"]]
    iocs = [e["node"] for e in d["stixCyberObservables"]["edges"]]

    top_iocs = sorted(iocs, key=lambda x: (x.get("x_opencti_score") or 0), reverse=True)[:5]
    return {
        "executive_summary": {
            "threat_landscape": f"{len(reports)} recent reports ingested; {len(iocs)} recent observables tracked.",
            "top_priority_iocs": top_iocs,
            "recommended_actions": [
                "Prioritize patching/mitigation for exposed assets referenced in high-risk reports.",
                "Harden identity workflows (MFA/conditional access) where credential/phishing themes dominate.",
                "Validate detection/response coverage for top observed infrastructure and malware families.",
            ],
        },
        "recent_reports": reports,
    }


@app.get("/roi")
def roi():
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
    ops_cost = 50  # demo cost unit
    value = (high * 5) - ops_cost
    return {
        "metrics": {
            "recent_observables": len(scores),
            "high_score_observables": high,
            "estimated_value_units": value,
        },
        "roi_explanation": "Demo ROI = (high_score_IOCs * 5) - ops_cost_units",
    }


router = APIRouter(prefix="/strategy")


def _wrap(fn):
    try:
        return fn()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run-daily")
def manual_daily():
    return {"status": "ok", "created": _wrap(run_daily)}


@router.post("/run-weekly")
def manual_weekly():
    return {"status": "ok", "created": _wrap(run_weekly)}


@router.post("/run-monthly")
def manual_monthly():
    return {"status": "ok", "created": _wrap(run_monthly)}


app.include_router(router)


@app.on_event("startup")
def _startup():
    start_scheduler()
 
