# Cyber Threat Intelligence Platform  
# Threat Intelligence Sharing & TAXII Dissemination Layer

---

# 📌 Overview

This feature implements secure threat intelligence sharing using:

- STIX 2.1 standard bundles  
- API key–protected partner access  
- Internal intelligence segmentation  
- TLP-based dissemination (CLEAR / AMBER / RED)  
- Source sanitization policies  
- Automated export from OpenCTI  
- Honeypot IOC pipeline integration  
- High-confidence IOC sharing feeds  
- Preview endpoints for validation before consumption  

It enables controlled intelligence sharing with:

- 🌍 Public community  
- 🏦 Industry partners  
- 🛡 Internal SOC teams  

---

# 🧠 Architecture (Dissemination Layer)

```
OpenCTI → TAXII Exporter → STIX Bundles on Disk → Sharing Gateway (API Key Protected)
```

Flow:

- OpenCTI stores reports, indicators, observables  
- taxii-exporter pulls data via GraphQL  
- Data is filtered and sanitized based on policy  
- STIX 2.1 bundles are generated into:

```
data/opencti-export/share/
```

- taxii-server serves them via HTTP endpoints  

---

# 📂 Directory Structure

```
data/opencti-export/share/
├── index.json
├── public/
│   └── bundle.json
├── partners/
│   └── bank/
│       ├── reports.json
│       ├── iocs_high.json
│       └── preview.json
└── internal/
    └── reports.json
```

---

# 🆕 New Feature: High-Confidence IOC Sharing

New endpoint provides curated, high-confidence indicators extracted from:

- Honeypot attacks  
- Confirmed malicious activity  
- Verified malicious infrastructure  
- Detection-ready indicators  

Endpoint:

```
/share/partners/bank/iocs_high.json
```

Example preview command:

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/iocs_high.json \
| jq '.objects[] | .type' | head
```

Example output:

```
"indicator"
"indicator"
"ipv4-addr"
"domain-name"
"file"
```

---

# 👁 Preview Endpoint (New)

Preview endpoint allows partners to validate feed safely before ingestion.

Endpoint:

```
/share/partners/bank/preview.json
```

Purpose:

- Validate structure
- Verify STIX compliance
- Confirm access permissions
- Test ingestion pipelines

Example:

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/preview.json | jq .
```

---

# 🔐 Intelligence Segmentation Model

| Feed | TLP | Auth Required | Content Scope |
|----|----|----|----|
| Public | CLEAR | ❌ No | Sanitized observables only |
| Partner | AMBER | ✅ Partner Key | Curated reports + indicators |
| Partner IOC Feed | AMBER | ✅ Partner Key | High-confidence IOCs |
| Partner Preview | AMBER | ✅ Partner Key | Preview sample |
| Internal | RED | ✅ Internal Key | Full intelligence set |

---

# 🏷 TLP Markings

The exporter automatically inserts STIX marking-definition:

```
marking-definition--tlp-clear
marking-definition--tlp-amber
marking-definition--tlp-red
```

Each bundle includes proper STIX 2.1 marking structure.

Example:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [...]
}
```

---

# ⚙️ How It Works Internally

Inside:

```
services/taxii-exporter/export.py
```

---

## Step 1 – Fetch from OpenCTI

Uses GraphQL:

- stixCyberObservables  
- reports  
- indicators  

Includes honeypot pipeline intelligence.

---

## Step 2 – Apply Partner Policy

Policy file:

```
services/taxii-exporter/policies/partners.yml
```

Example:

```yaml
bank:
  tlp: amber
  include_reports: true
  include_high_confidence_iocs: true
  max_observables: 200
  max_reports: 20
  sanitize_reports: true
  allowed_labels:
    - otx
    - osint
    - linux
    - honeypot
```

---

## Step 3 – Filter Logic

Exporter applies:

- Limit by max_observables  
- Limit by max_reports  
- Filter by allowed_labels  
- Filter by source  
- Filter by confidence score  
- Apply sanitization if enabled  

---

## Step 4 – Generate STIX Bundle

Creates:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [...]
}
```

Files generated:

```
reports.json
iocs_high.json
preview.json
```

---

# 🔎 Source Sanitization

When sanitize_reports: true, exporter removes:

- createdBy  
- external references  
- internal labels  
- internal scoring metadata  
- connector metadata  
- internal enrichment traces  

This protects:

- Internal sources  
- Investigation notes  
- Analyst comments  
- Attribution confidence  

---

# 🔑 API Key Security Model

## Partner Access

Header required:

```
X-API-Key: BANK123
```

Without key:

```
401 Unauthorized
```

---

## Internal Access

Header required:

```
X-Internal-Key: INTERNAL123
```

Without key:

```
401 Unauthorized
```

---

# 🚀 How To Start

Start everything:

```bash
docker compose up -d --build
```

Restart sharing layer:

```bash
docker compose up -d --force-recreate taxii-exporter taxii-server
```

---

# 🔄 Manual Export Trigger

Force re-export:

```bash
docker compose exec taxii-exporter sh -lc \
'python -c "import export; export.export_collections()"'
```

---

# 🧹 Reset Export Data

```bash
rm -rf data/opencti-export/share
rm -f data/opencti-export/bundle.json

docker compose up -d --force-recreate taxii-exporter taxii-server

docker compose exec taxii-exporter sh -lc \
'python -c "import export; export.export_collections()"'
```

---

# 🧪 Testing & Validation

---

## 1️⃣ Check index

```bash
curl -s http://localhost:9000/share/index.json | jq .
```

Expected:

```
generated_at
lookback_days
paths
```

---

## 2️⃣ Public Feed

```bash
curl -s http://localhost:9000/share/public/bundle.json \
| grep -m 1 '"definition":'
```

Expected:

```
"tlp": "clear"
```

---

## 3️⃣ Partner Feed

Without Key:

```bash
curl -i http://localhost:9000/share/partners/bank/reports.json
```

Expected:

```
401 Unauthorized
```

With Key:

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/reports.json \
| grep -c '"type": "report"'
```

---

## 4️⃣ Partner High-Confidence IOC Feed

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/iocs_high.json \
| jq '.objects[] | .type' | head
```

---

## 5️⃣ Partner Preview Endpoint

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/preview.json | jq .
```

---

## 6️⃣ Internal Feed

Without Key:

```bash
curl -i http://localhost:9000/share/internal/reports.json
```

With Key:

```bash
curl -s -H "X-Internal-Key: INTERNAL123" \
http://localhost:9000/share/internal/reports.json
```

---

# 🧩 Use Cases

🏦 Industry Partner Sharing  
Share curated intelligence safely.

🌍 Community Intelligence  
Provide public threat indicators.

🛡 SOC Operations  
Maintain full internal intelligence.

🤖 Automated Blocking  
Use IOC feed for automated defense.

---

# 🛠 Debugging Guide

Check logs:

```bash
docker compose logs --tail=50 taxii-exporter
```

Verify files:

```bash
ls data/opencti-export/share/partners/bank/
```

Expected:

```
reports.json
iocs_high.json
preview.json
```

---

# 🧠 Workflow Summary

```
RSS + Honeypot → OpenCTI → Exporter → Filter → Sanitize → STIX → API Sharing
```

---

# 🏆 Security Controls Implemented

- API key enforcement  
- TLP segmentation  
- Label filtering  
- Source sanitization  
- Report limiting  
- Observable limiting  
- Partner-specific feeds  
- Preview validation endpoint  
- STIX 2.1 compliance  

---

# 🔮 Future Enhancements

- TAXII 2.1 collections
- OAuth2 authentication
- Rate limiting
- Audit logging
- Feed analytics

---

# ✅ Current Status

✔ Public feed working  
✔ Partner feed working  
✔ High-confidence IOC feed working  
✔ Preview endpoint working  
✔ Internal feed working  
✔ API security working  
✔ STIX 2.1 compliant  

---
