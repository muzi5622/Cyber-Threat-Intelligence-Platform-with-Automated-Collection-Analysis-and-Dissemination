# 🛡️ Cyber Threat Intelligence Platform (CTI)
**Automated Collection, ML-Driven Analysis, Strategic Decision-Making, and Secure Intelligence Sharing**

Enterprise-grade Cyber Threat Intelligence (CTI) platform that automates the full intelligence lifecycle — from OSINT and honeypot collection to machine-learning attribution, executive decision support, and secure STIX/TAXII intelligence sharing.

Built around OpenCTI, Elasticsearch, and custom ML pipelines.

---

# 📌 Overview

This platform implements a complete intelligence pipeline:

```

Collection → Enrichment → Attribution → Correlation → Strategic Decision → Dissemination

```

It transforms raw threat data into:

- Structured CTI
- Threat actor attribution
- Executive-level risk reports
- Actionable BLOCK / MONITOR / IGNORE decisions
- Secure partner intelligence feeds

---

# 🚀 Key Features

## Automated Intelligence Collection

- RSS threat intelligence ingestion
- AlienVault OTX integration
- URLHaus malicious URL ingestion
- MITRE ATT&CK integration
- Honeypot log ingestion via Logstash → Elasticsearch

---

## IOC Extraction and Enrichment

### Rule-based NLP extraction

Extracts:

- IPv4 / IPv6
- Domains
- URLs
- MD5 / SHA1 / SHA256 hashes
- CVEs

### ML-based NER extraction

Transformer model:

```

muzi5622/cti-ner-model

```

Provides:

- Context-aware IOC extraction
- Improved accuracy over regex
- Label-based enrichment

---

## ML-Based Threat Actor Attribution (Honeypot Intelligence)

Uses honeypot logs to automatically:

- Profile attacker behavior
- Classify attackers (scanner, botnet, bruteforce)
- Cluster attackers
- Create Threat Actor entities in OpenCTI
- Link Indicators → Threat Actors

Model source:

```

muzi5622/actor-profiler-model

```

---

## Strategic Decision Engine

Automatically generates executive reports:

- Daily Executive Cyber Brief
- Weekly Cyber Risk Brief
- Monthly Risk Assessment

Provides automated decisions:

```

BLOCK
MONITOR
IGNORE

```

Based on:

- Threat severity
- Confidence
- Recency
- Intelligence correlation

API available at:

```

[http://localhost:8000/docs](http://localhost:8000/docs)

```

---

## Secure Intelligence Sharing (STIX 2.1 / TAXII-style)

Exports intelligence into:

- Public feeds
- Partner feeds
- Internal feeds

Supports:

- API key authentication
- TLP classification (CLEAR, AMBER, RED)
- Partner-specific filtering
- Intelligence sanitization

---

# 🏗 Architecture
```
===============================================================================
        CYBER THREAT INTELLIGENCE PLATFORM — 5-LAYER ARCHITECTURE
===============================================================================


┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — SOURCES & SENSORS                                                 │
└─────────────────────────────────────────────────────────────────────────────┘

     ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐
     │ RSS / OSINT  │   │ AlienVault   │   │ URLHaus      │   │ MITRE ATT&CK│
     │ Feeds        │   │ OTX Feed     │   │ Malware Feed │   │ Knowledge   │
     └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └─────┬───────┘
            │                  │                  │                 │
            └────────────┬─────┴──────────┬──────┴──────────┬───────┘
                         │                │                 │
                   ┌─────▼────────────────▼─────────────────▼─────┐
                   │ Honeyport Sensor (Honeypot)                  │
                   └──────────────────────────────────────────────┘



┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2 — COLLECTION SERVICES                                              │
└─────────────────────────────────────────────────────────────────────────────┘

                ┌──────────────────┐
                │ rss-ingestor     │◄──── RSS feeds
                └────────┬─────────┘
          
              ┌──────────────────────────────┐
              │ Threat Feed Connector        │◄──── OTX / URLHaus / MITRE
              └────────┬─────────────────────┘
        
              ┌──────────────────┐
              │ honeyport        │◄──── Honeypot sensor
              └────────┬─────────┘
                       │
                       ▼
                ┌──────────────┐
                │ Logstash     │
                │ Pipeline     │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │ SQLite State │
                │ Database     │
                └──────────────┘



┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3 — CTI CORE (OpenCTI Intelligence Graph)                            │
└─────────────────────────────────────────────────────────────────────────────┘

                       ┌────────────────────────────┐
                       │ OpenCTI GraphQL API        │
                       └─────────────┬──────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
        
         ┌───────────────┐   ┌────────────────┐   ┌────────────────┐
         │ Intelligence  │   │ Elasticsearch  │   │ Threat Reports │
         │ Graph         │   │ Storage        │   │ Indicators     │
         │               │   │                │   │ Threat Actors  │
         │ Relationships │   │ Indexed Intel  │   │ CVEs           │
         └───────────────┘   └────────────────┘   └────────────────┘



┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4 — ENRICHMENT & ANALYSIS                                            │
└─────────────────────────────────────────────────────────────────────────────┘
    
                    ┌────────────────────┐
                    │ NLP Enricher       │
                    │ (Regex Extraction) │
                    └─────────┬──────────┘
                              │
        
                    ┌────────────────────┐
                    │ ML NER Enricher    │
                    │ (Transformer ML)   │
                    └─────────┬──────────┘
                              │
        
                    ┌────────────────────┐
                    │ Actor Profiler     │
                    │ (ML Attribution)   │
                    └─────────┬──────────┘
                              │
        
                    ┌────────────────────┐
                    │ Confidence Scoring │
                    └─────────┬──────────┘
                              │
                              ▼
        
                ┌─────────────────────────────┐
                │ Strategic Decision Engine   │
                │                             │
                │  Decisions Generated:       │
                │  • BLOCK                    │
                │  • MONITOR                  │
                │  • IGNORE                   │
                └──────────────────────────────┘



┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5 — DISSEMINATION & CONSUMERS                                        │
└─────────────────────────────────────────────────────────────────────────────┘

          ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
          │ SIEM / SOAR  │   │ SOC Analysts │   │ Kibana       │
          │ Detection    │   │ Investigation│   │ Dashboards   │
          └──────────────┘   └──────────────┘   └──────────────┘
    
          ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
          │ Executive    │   │ Intel API    │   │ TAXII Export │
          │ Reports      │   │              │   │              │
          └──────┬───────┘   └──────────────┘   └──────┬───────┘
                 │                                     │
                 ▼                                     ▼
    
            ┌──────────────┐                  ┌──────────────┐
            │ TAXII Server │ ───────────────► │ Partners /   │
            │              │                  │ ISAC / SOC   │
            └──────────────┘                  └──────────────┘



===============================================================================
INTELLIGENCE FLOW SUMMARY
===============================================================================

Sources → Collection → OpenCTI Intelligence Graph → Enrichment & ML →
Decision Engine → SIEM / SOC / TAXII / Executive Reports


===============================================================================
KEY CAPABILITIES
===============================================================================

• Automated OSINT and honeypot collection
• ML-based IOC extraction and threat actor attribution
• Confidence scoring and strategic decision automation
• Intelligence graph correlation
• Executive risk reporting
• STIX/TAXII intelligence sharing
• SOC and SIEM integration

===============================================================================


```

![architecture digram](architecture.svg)
---

# 🐳 Services

| Service | Port | Purpose |
|--------|------|---------|
| OpenCTI | 8080 | CTI platform |
| Intel API | 8000 | Strategic reports |
| TAXII Server | 9000 | Intelligence sharing |
| Kibana | 5601 | Log visualization |
| RabbitMQ | 15672 | Message queue |
| Elasticsearch | 9200 | Data storage |
| Logstash | 5044 | Honeypot ingestion |

---

# ⚙️ Requirements

Recommended system:

- Ubuntu 22.04+
- Docker
- Docker Compose
- 8GB RAM minimum (16GB recommended)

Install Docker:

```bash
sudo apt update
sudo apt install docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
````

---

# 🔐 Environment Setup

Create `.env` file:

```env
OPENCTI_ADMIN_EMAIL=admin@demo.local
OPENCTI_ADMIN_PASSWORD=ChangeMe123!
OPENCTI_ADMIN_TOKEN=change_me_token

APP_BASE_URL=http://localhost:8080

RABBITMQ_USER=opencti
RABBITMQ_PASS=opencti_password

MINIO_USER=opencti
MINIO_PASS=opencti_password

CONNECTOR_URLHAUS_ID=id-urlhaus
CONNECTOR_ALIENVAULT_ID=id-otx
CONNECTOR_MITRE_ID=id-mitre

OTX_API_KEY=your_otx_key

PARTNER_API_KEY=BANK123
INTERNAL_API_KEY=INTERNAL123
```

---

# ▶️ Start Platform

Start all services:

```bash
docker compose up -d --build
```

Check running services:

```bash
docker compose ps
```

Expected output:

```
opencti            running
rss-ingestor       running
nlp-enricher       running
ml-ner-enricher    running
actor-profiler     running
intel-api          running
taxii-server       running
```

---

# 🌐 Access Interfaces

OpenCTI:

```
http://localhost:8080
```

Intel API:

```
http://localhost:8000/docs
```

Kibana:

```
http://localhost:5601
```

RabbitMQ:

```
http://localhost:15672
```

TAXII Feed:

```
http://localhost:9000/share/public/bundle.json
```

---

# 🔎 Operational Verification Commands

## Check OpenCTI health

```bash
curl http://localhost:8080/graphql \
  -H "Authorization: Bearer $OPENCTI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { about { version } }"}'
```

---

## Check RSS ingestion

```bash
docker compose logs -f rss-ingestor
```

Expected:

```
created report: Threat Report Title
```

---

## Check NLP enrichment

```bash
docker compose logs -f nlp-enricher
```

Expected:

```
Extracted IOCs: 12
Created observable
```

---

## Check ML enrichment

```bash
docker compose logs -f ml-ner-enricher
```

Expected:

```
cycle done new=5 processed_total=120
```

---

## Check actor profiler

```bash
docker compose logs -f actor-profiler
```

Expected:

```
Built features for 312 IPs
Created threat actor HP-ACTOR-001
```

---

## Check strategic engine

Run manual report:

```bash
curl -X POST http://localhost:8000/strategy/run-daily
```

Check logs:

```bash
docker compose logs -f intel-api
```

---

## Check TAXII feed

Public feed:

```bash
curl http://localhost:9000/share/public/bundle.json | jq .
```

Partner feed:

```bash
curl -H "X-API-Key: BANK123" \
http://localhost:9000/share/partners/bank/iocs_high.json
```

---

# 📊 Verify Intelligence in OpenCTI

Open UI:

```
http://localhost:8080
```

Check:

```
Knowledge → Reports
Knowledge → Observables
Threat Actors
Indicators
```

You should see automatically created intelligence.

---

# 🧪 Check Honeypot Pipeline

Verify logs indexed:

```bash
curl http://localhost:9200/honeypot-logs-*/_search?pretty
```

View in Kibana:

```
http://localhost:5601
```

---

# 🛠 Useful Commands

Restart platform:

```bash
docker compose restart
```

Stop platform:

```bash
docker compose down
```

Full reset:

```bash
docker compose down -v
rm -rf data/*
```

Rebuild specific service:

```bash
docker compose build actor-profiler
docker compose up -d actor-profiler
```

---

# 🔄 Automation Schedule

| Task              | Frequency                |
| ----------------- | ------------------------ |
| RSS ingestion     | 5 minutes                |
| NLP enrichment    | 2 minutes                |
| ML enrichment     | 1 minute                 |
| Actor profiling   | 5 minutes                |
| Strategic reports | Daily / Weekly / Monthly |
| TAXII export      | 5 minutes                |

---

# 📂 Project Structure

```
services/
  rss-ingestor/
  nlp-enricher/
  ml-ner-enricher/
  actor-profiler/
  intel-api/
  taxii-exporter/

data/
logstash/
docker-compose.yml
.env
```

---

# 🎓 What This Platform Demonstrates

* Full CTI lifecycle automation
* ML-based threat actor attribution
* Executive intelligence reporting
* Automated intelligence sharing
* SOC-grade architecture
* Enterprise CTI engineering practices

---

# 👨‍💻 Author

Muzammal
Cyber Threat Intelligence Platform

---

# 📜 License

Educational and research use.
