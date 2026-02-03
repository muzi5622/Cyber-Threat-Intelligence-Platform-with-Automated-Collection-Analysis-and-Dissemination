import os
import requests
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class OpenCTIClient:
    def __init__(self):
        self.base_url = os.getenv("OPENCTI_BASE", "http://opencti:8080").rstrip("/")
        self.token = os.getenv("OPENCTI_TOKEN", "")
        if not self.token:
            raise RuntimeError("OPENCTI_TOKEN is not set")

        self.endpoint = f"{self.base_url}/graphql"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            }
        )

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        r = self.session.post(self.endpoint, json={"query": query, "variables": variables or {}}, timeout=30)
        r.raise_for_status()
        data = r.json()
        if "errors" in data:
            raise RuntimeError(data["errors"])
        return data["data"]

    # ---- Queries ----
    def list_reports(self, start_iso: str, end_iso: str, first: int = 200) -> Dict[str, Any]:
        # ✅ removed x_opencti_score (not on Report in your schema)
        q = """
        query Reports($filters: FilterGroup, $first: Int!) {
          reports(filters: $filters, first: $first, orderBy: created_at, orderMode: desc) {
            edges {
              node {
                id
                name
                description
                created_at
                confidence
                report_types
                x_opencti_reliability
              }
            }
          }
        }
        """
        filters = {
            "mode": "and",
            "filters": [
                {"key": "created_at", "values": [start_iso], "operator": "gt"},
                {"key": "created_at", "values": [end_iso], "operator": "lt"},
            ],
            "filterGroups": [],
        }
        return self.graphql(q, {"filters": filters, "first": first})

    def list_observables(self, start_iso: str, end_iso: str, first: int = 500) -> Dict[str, Any]:
        q = """
        query Observables($filters: FilterGroup, $first: Int!) {
          stixCyberObservables(filters: $filters, first: $first, orderBy: created_at, orderMode: desc) {
            edges {
              node {
                id
                observable_value
                entity_type
                created_at
                confidence
                x_opencti_score
              }
            }
          }
        }
        """
        filters = {
            "mode": "and",
            "filters": [
                {"key": "created_at", "values": [start_iso], "operator": "gt"},
                {"key": "created_at", "values": [end_iso], "operator": "lt"},
            ],
            "filterGroups": [],
        }
        return self.graphql(q, {"filters": filters, "first": first})

    # ---- Mutations ----
    def create_report(self, name: str, description: str, confidence: int = 70) -> str:
        # ✅ your schema: published is NON_NULL DateTime, not boolean
        # ✅ report_types is optional list, but we set a safe default
        q = """
        mutation CreateReport($input: ReportAddInput!) {
          reportAdd(input: $input) { id }
        }
        """
        published_dt = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        variables = {
            "input": {
                "name": name,
                "description": description,
                "confidence": confidence,
                "published": published_dt,
                "report_types": ["threat-report"],
            }
        }
        return self.graphql(q, variables)["reportAdd"]["id"]
 
