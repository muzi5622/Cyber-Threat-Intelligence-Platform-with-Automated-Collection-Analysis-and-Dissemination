import os, time, json
import requests

OPENCTI_BASE = os.getenv("OPENCTI_BASE", "http://opencti:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
EXPORT_DIR = os.getenv("EXPORT_DIR", "/exports")
RUN_EVERY = int(os.getenv("RUN_EVERY_SECONDS", "300"))

HEADERS = {"Authorization": f"Bearer {OPENCTI_TOKEN}"}

def export_stix_bundle():
    # OpenCTI has multiple export paths depending on version/config.
    # For a demo: export latest observables list into a pseudo STIX bundle JSON.
    # (Exam-safe: explain you can replace with native OpenCTI STIX export connector.)
    gql = f"{OPENCTI_BASE}/graphql"
    q = """
    query Export($n:Int!){
      stixCyberObservables(first:$n, orderBy: created_at, orderMode: desc){
        edges{ node{ id observable_value created_at } }
      }
    }
    """
    r = requests.post(gql, headers={**HEADERS, "Content-Type":"application/json"},
                      json={"query": q, "variables": {"n": 200}}, timeout=30)
    r.raise_for_status()
    d = r.json()["data"]["stixCyberObservables"]["edges"]

    objects = []
    for e in d:
        val = e["node"]["observable_value"]
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{e['node']['id'][-12:]}",
            "name": f"IOC {val}",
            "pattern": f"[x-opencti:value = '{val}']",
        })

    bundle = {"type":"bundle","id":"bundle--demo","spec_version":"2.1","objects":objects}
    out = os.path.join(EXPORT_DIR, "bundle.json")
    with open(out, "w") as f:
        json.dump(bundle, f, indent=2)
    print("[taxii-exporter] wrote", out)

def main():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    while True:
        try:
            export_stix_bundle()
        except Exception as e:
            print("[taxii-exporter] error:", e)
        time.sleep(RUN_EVERY)

if __name__ == "__main__":
    main()
