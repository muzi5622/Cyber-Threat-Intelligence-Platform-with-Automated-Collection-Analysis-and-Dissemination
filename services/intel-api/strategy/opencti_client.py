import os
import requests
from typing import Dict, Any, Optional, List
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
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        )

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        r = self.session.post(self.endpoint, json={"query": query, "variables": variables or {}}, timeout=30)
        r.raise_for_status()
        data = r.json()
        if "errors" in data:
            raise RuntimeError(data["errors"])
        return data["data"]

    # -------------------------
    # READ
    # -------------------------
    def list_reports(
        self,
        start_iso: str,
        end_iso: str,
        first: int = 200,
        exclude_name_prefixes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
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

        data = self.graphql(q, {"filters": filters, "first": first})

        prefixes = tuple(exclude_name_prefixes or [])
        if not prefixes:
            return data

        kept = []
        for e in data.get("reports", {}).get("edges", []):
            name = (e.get("node", {}).get("name") or "")
            if name.startswith(prefixes):
                continue
            kept.append(e)

        data["reports"]["edges"] = kept
        return data

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

    # -------------------------
    # LABEL HELPERS
    # -------------------------
    def ensure_label_id(self, value: str) -> str:
        """Find a label by value; create if missing; return label ID."""
        q_search = """
        query FindLabel($search: String) {
          labels(search: $search, first: 1) {
            edges { node { id value } }
          }
        }
        """
        data = self.graphql(q_search, {"search": value})
        edges = data.get("labels", {}).get("edges", [])
        if edges:
            return edges[0]["node"]["id"]

        q_add = """
        mutation AddLabel($input: LabelAddInput!) {
          labelAdd(input: $input) { id }
        }
        """
        created = self.graphql(q_add, {"input": {"value": value}})
        return created["labelAdd"]["id"]

    # -------------------------
    # WRITE
    # -------------------------
    def create_report(
        self,
        name: str,
        description: str,
        confidence: int = 70,
        tag_values: Optional[List[str]] = None,
    ) -> str:
        """
        OpenCTI 6.9.15 can be picky about how labels are passed.
        We try 3 variants in order:
          1) objectLabel as label IDs
          2) objectLabel as label values (strings)
          3) no objectLabel (always works)
        """
        q = """
        mutation CreateReport($input: ReportAddInput!) {
          reportAdd(input: $input) { id }
        }
        """
        published_dt = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        base_input: Dict[str, Any] = {
            "name": name,
            "description": description,
            "confidence": confidence,
            "published": published_dt,
            "report_types": ["threat-report"],
        }

        # 3) always works
        def create_plain() -> str:
            return self.graphql(q, {"input": base_input})["reportAdd"]["id"]

        if not tag_values:
            return create_plain()

        # Ensure labels exist
        label_ids = [self.ensure_label_id(v) for v in tag_values]

        # 1) Try with label IDs
        try:
            inp = dict(base_input)
            inp["objectLabel"] = label_ids
            return self.graphql(q, {"input": inp})["reportAdd"]["id"]
        except Exception:
            pass

        # 2) Try with label VALUES
        try:
            inp = dict(base_input)
            inp["objectLabel"] = tag_values
            return self.graphql(q, {"input": inp})["reportAdd"]["id"]
        except Exception:
            pass

        # 3) fallback: create without tags (never fail report creation)
        return create_plain()
 
