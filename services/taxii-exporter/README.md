# Cyber Threat Intelligence Platform  
## Threat Intelligence Sharing & TAXII Dissemination Layer

---

# 📌 Overview

This feature implements **secure threat intelligence sharing** using:

- STIX 2.1 standard bundles
- API key–protected partner access
- Internal intelligence segmentation
- TLP-based dissemination (CLEAR / AMBER / RED)
- Source sanitization policies
- Automated export from OpenCTI

It enables controlled intelligence sharing with:

- 🌍 Public community
- 🏦 Industry partners
- 🛡 Internal SOC teams

---

# 🧠 Architecture (Dissemination Layer)

OpenCTI → TAXII Exporter → STIX Bundles on Disk → Sharing Gateway (API Key Protected)

### Flow:

1. OpenCTI stores reports, indicators, observables.
2. `taxii-exporter` pulls data via GraphQL.
3. Data is filtered + sanitized based on policy.
4. STIX 2.1 bundles are generated into:

```
data/opencti-export/share/
```

5. `taxii-server` serves them via HTTP endpoints.

---

# 📂 Directory Structure

```
data/opencti-export/share/
├── index.json
├── public/
│   └── bundle.json
├── partners/
│   └── bank/
│       └── reports.json
└── internal/
    └── reports.json
```

---

# 🔐 Intelligence Segmentation Model

| Feed      | TLP      | Auth Required | Content Scope |
|-----------|----------|--------------|---------------|
| Public    | CLEAR    | ❌ No        | Sanitized observables only |
| Partner   | AMBER    | ✅ Partner Key | Curated reports + indicators |
| Internal  | RED      | ✅ Internal Key | Full intelligence set |

---

# 🏷 TLP Markings

The exporter automatically inserts STIX marking-definition:

- `marking-definition--tlp-clear`
- `marking-definition--tlp-amber`
- `marking-definition--tlp-red`

Each bundle includes proper STIX 2.1 marking structure.

---

# ⚙️ How It Works Internally

## 1️⃣ Export Process

Inside `services/taxii-exporter/export.py`

### Step 1 – Fetch from OpenCTI

Uses GraphQL:
- `stixCyberObservables`
- `reports`

### Step 2 – Apply Partner Policy

Policy file:

```
services/taxii-exporter/policies/partners.yml
```

Example:

```yaml
bank:
  tlp: amber
  include_reports: true
  max_observables: 200
  max_reports: 20
  sanitize_reports: true
  allowed_labels:
    - otx
    - osint
    - linux
```

### Step 3 – Filter Logic

- Limit by max_observables
- Limit by max_reports
- Filter by allowed_labels
- Filter by source (e.g. OTX)
- Apply sanitization if enabled

### Step 4 – Generate STIX Bundle

Creates:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [...]
}
```

---

# 🔎 Source Sanitization

When `sanitize_reports: true`, exporter removes:

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
401 Unauthorized (partner)
```

## Internal Access

Header required:

```
X-Internal-Key: INTERNAL123
```

Without key:

```
401 Unauthorized (internal)
```

---

# 🚀 How To Start

## Start Everything

```bash
docker compose up -d --build
```

## Restart Only Sharing Layer

```bash
docker compose up -d --force-recreate taxii-exporter taxii-server
```

---

# 🔄 Manual Export Trigger

Force re-export:

```bash
docker compose exec taxii-exporter sh -lc 'python -c "import export; export.export_collections()"'
```

---

# 🧹 Reset Export Data (Fresh Regeneration)

```bash
rm -rf data/opencti-export/share
rm -f data/opencti-export/bundle.json

docker compose up -d --force-recreate taxii-exporter taxii-server

docker compose exec taxii-exporter sh -lc 'python -c "import export; export.export_collections()"'
```

---

# 🧪 Testing & Validation

## 1️⃣ Check index

```bash
curl -s http://localhost:9000/share/index.json | jq .
```

Expected:
- generated_at
- lookback_days
- paths

---

## 2️⃣ Public Feed

```bash
curl -s http://localhost:9000/share/public/bundle.json | grep -m 1 '"definition":'
```

Should show:
```
"tlp": "clear"
```

---

## 3️⃣ Partner Feed

### Without Key

```bash
curl -i http://localhost:9000/share/partners/bank/reports.json
```

Expected:
```
401 Unauthorized
```

### With Key

```bash
curl -s -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/reports.json \
| grep -c '"type": "report"'
```

Expected:
```
5
```

---

## 4️⃣ Internal Feed

### Without Key

```bash
curl -i http://localhost:9000/share/internal/reports.json
```

Expected:
```
401 Unauthorized
```

### With Key

```bash
curl -s -H "X-Internal-Key: INTERNAL123" \
http://localhost:9000/share/internal/reports.json \
| grep -c '"type": "report"'
```

Expected:
```
50
```

---

# 🧩 Use Cases

### 🏦 Industry Partner Sharing
Share curated OTX-derived intelligence without exposing internal investigations.

### 🌍 Community Intelligence
Provide CLEAR-level indicators to public researchers.

### 🛡 SOC Operations
Maintain RED-level full feed internally.

### 📈 Regulatory Compliance
Segment intelligence per TLP requirements.

---

# 🛠 Debugging Guide

## Container restarting?

Check logs:

```bash
docker compose logs --tail=50 taxii-exporter
```

## Unauthorized error?

Ensure correct header:

```
X-API-Key
X-Internal-Key
```

## No reports showing?

Check:
- partners.yml allowed_labels
- OpenCTI actually contains labeled data
- max_reports limit

---

# 🧠 Workflow Summary

1. RSS Ingestor pulls feeds.
2. NLP + ML enrich content.
3. Intel API scores intelligence.
4. OpenCTI stores enriched objects.
5. TAXII exporter filters & sanitizes.
6. Sharing server exposes STIX bundles securely.

---

# 🏆 Security Controls Implemented

- API key enforcement
- TLP segmentation
- Label filtering
- Source sanitization
- Report limiting
- Observable limiting
- Partner-specific collections
- STIX 2.1 compliance

---

# 🎓 How To Explain in Viva / Presentation

> “We implemented a three-tier intelligence dissemination model using STIX 2.1. Intelligence is exported from OpenCTI, filtered by partner policy, sanitized for source protection, marked with TLP definitions, and securely shared via API-key protected endpoints. Public, partner, and internal feeds are segmented to enforce least privilege intelligence sharing.”

---

# 📌 Important Notes

405 Method Not Allowed is normal for HEAD requests.  
Use GET instead.

Curl pipe error `Failure writing output` is harmless (caused by head).

---

# 🔮 Future Enhancements

- Multi-partner dynamic provisioning
- OAuth2 instead of static API keys
- Real TAXII 2.1 Collections API
- Per-partner dynamic label filtering
- Rate limiting
- Audit logging
- Feed usage tracking
- Download statistics

---

# ✅ Current Status

✔ Public feed working  
✔ Partner API key enforcement working  
✔ Internal API key enforcement working  
✔ STIX 2.1 compliant bundles  
✔ TLP marking included  
✔ Source sanitization functional  
✔ Policy-based filtering active  

---
