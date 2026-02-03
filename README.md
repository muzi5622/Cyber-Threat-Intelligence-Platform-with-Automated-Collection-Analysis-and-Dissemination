# 🛡️ CTI Platform Exam Project (EduQual Level 6)

### Automated Cyber Threat Intelligence with Strategic Decision-Making

**Project Title**

**Comprehensive Cyber Threat Intelligence Platform with Automated Collection, Analysis, and Dissemination for Strategic Security Decision Making**

**Student:** Muzammal

**Qualification:** Diploma in Artificial Intelligence Operations (EduQual Level 6)

**Core Technologies**

OpenCTI · OSINT (RSS + URLHaus) · NLP / IOC Extraction · **Strategic Decision Engine** · STIX 2.1 · TAXII-style Sharing · Docker Compose

---

## 1. Project Overview

This project implements a **fully automated Cyber Threat Intelligence (CTI) platform** designed to support **strategic security decision-making**, not just IOC collection.

The platform follows a real-world intelligence lifecycle used by SOCs, MSSPs, and CERT teams:

> **Collection → Analysis → Strategic Decision → Dissemination**

A dedicated **Strategic Decision Engine** automatically evaluates intelligence stored in OpenCTI, prioritizes threats, and produces **executive-level intelligence reports** with clear security decisions.

---

## 2. Key Capabilities

✔ Automated OSINT collection (RSS, URLHaus)

✔ AI-assisted IOC extraction and enrichment

✔ Centralized intelligence graph (OpenCTI)

✔ **Automated threat prioritization**

✔ **BLOCK / MONITOR / IGNORE decisions**

✔ **Daily & weekly strategic intelligence reports**

✔ STIX 2.1 export and TAXII-style sharing

✔ Fully containerized and autonomous


This platform answers:

> “What threats matter most, and what should we do now?”

---

## 3. End-to-End Automated Flow

```
OSINT Sources (RSS, URLHaus)
        ↓
OpenCTI Reports
        ↓
NLP Enrichment (IOC Extraction)
        ↓
Correlated Intelligence (OpenCTI Graph)
        ↓
Strategic Decision Engine (intel-api)
        ↓
Executive Reports & Decisions
        ↓
STIX 2.1 Bundles
        ↓
TAXII-style Distribution
```

---

## 4. Architecture Overview (Layered Design)


![architecture digram](architecture.png)


The system is intentionally layered to reflect **industry CTI architectures**.

---

### 🔹 Layer 1 — Core Platform Dependencies

These services support OpenCTI and all automation layers.

| Service       | Purpose                      |
| ------------- | ---------------------------- |
| Redis         | Caching and internal queues  |
| Elasticsearch | Indexing and search backend  |
| RabbitMQ      | Asynchronous task processing |
| MinIO         | Object storage for OpenCTI   |

---

### 🔹 Layer 2 — CTI Knowledge Base

**OpenCTI Platform**

* Central CTI repository and analyst dashboard
* Stores reports, observables, indicators, and relationships
* Provides a GraphQL API for automation

**OpenCTI Worker**

* Processes background jobs (imports, enrichment, rules)
* Enables scalable CTI processing

---

### 🔹 Layer 3 — Automated CTI Pipeline

#### RSS Ingestor (Custom, Automated)

* Collects threat intelligence from curated RSS feeds
* Converts articles into structured **OpenCTI Reports**
* Prevents duplication using local state tracking
* Runs continuously on a fixed schedule

#### URLHaus Connector

* Imports malicious URL intelligence once per day
* Adds high-confidence external threat data
* Operates with low resource usage

#### NLP Enricher (Custom, Automated)

* Processes recent OpenCTI reports
* Extracts:

  * Domains, URLs
  * IPv4 / IPv6 addresses
  * File hashes (MD5, SHA1, SHA256)
  * CVEs
* Creates STIX Observables and Indicators
* Applies labels and confidence scores

---

### 🔹 Layer 4 — Strategic Decision-Making ⭐ (Core Feature)

**Strategic Decision Engine (intel-api)**

This service transforms intelligence into **actionable security decisions**.

It automatically:

* Pulls recent intelligence from OpenCTI
* Scores each report based on:

  * Confidence
  * Severity keywords (ransomware, exploit, phishing, etc.)
  * Organizational relevance
  * Recency
* Assigns decisions:

  * **BLOCK**
  * **MONITOR**
  * **IGNORE**
* Detects threat themes and trends
* Generates **executive-ready strategic reports**

This layer turns OpenCTI into a **decision support system**, not just a data store.

---

### 🔹 Layer 5 — Dissemination & Sharing

**STIX Exporter (Custom)**

* Exports OpenCTI intelligence into STIX 2.1 bundles on disk

**TAXII Server**

* Serves STIX bundles via HTTP
* Simulates organizational and inter-organizational CTI sharing

---
## Requirements

* Ubuntu 22.04+ (recommended)
* Docker Engine
* Docker Compose plugin

### Docker Installation (Ubuntu)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

---

##  Environment Configuration

Create `.env` in the project root:

```env
OPENCTI_ADMIN_EMAIL=admin@demo.local
OPENCTI_ADMIN_PASSWORD=ChangeMe_Admin123!
OPENCTI_ADMIN_TOKEN=CHANGE_ME_TOKEN

RABBITMQ_USER=opencti
RABBITMQ_PASS=opencti_password

MINIO_USER=opencti
MINIO_PASS=opencti_password

APP_BASE_URL=http://localhost:8080
```

Load environment variables when using CLI tools:

```bash
set -a; source ./.env; set +a
```

---

## 8. Running the Platform

```bash
docker compose up -d --build
docker compose ps
```

---

##  Access URLs

* OpenCTI Dashboard
  `http://<server-ip>:8080`

* RabbitMQ Management
  `http://<server-ip>:15672`

* SpiderFoot UI
  `http://<server-ip>:5001`

* SpiderFoot (Clean URL)
  `http://<server-ip>:5002/spiderfoot`

* STIX Bundle
  `http://<server-ip>:9000/bundle.json`

---

##  Automation Verification (Evidence)

### RSS Collection

```bash
docker compose logs -f rss-ingestor
```

### NLP Enrichment

```bash
docker compose logs -f nlp-enricher
```

### SpiderFoot Automation

```bash
docker compose logs -f spiderfoot-automation
```

### TAXII Output

```bash
curl http://127.0.0.1:9000/bundle.json | head -n 40
```

---

##  Stop and Reset

Stop services:

```bash
docker compose down
```

Full reset:

```bash
docker compose down -v
rm -rf data/rss data/nlp data/spiderfoot-automation data/opencti-export
```

---

##  Strategic Intelligence Outputs

### Daily Executive Summary (Automated)

Generated automatically every day.

Includes:

* Threat landscape overview
* Top threat themes
* Highest-priority threats
* BLOCK / MONITOR / IGNORE decisions
* Immediate security recommendations

📍 **OpenCTI → Knowledge → Reports**

---

### Weekly Strategic Risk Brief (Automated)

Generated weekly.

Includes:

* Trend analysis
* Risk distribution
* Leadership-level actions and priorities

📍 **OpenCTI → Knowledge → Reports**

---

##  Docker Services Summary

| Service                         | Port         | Layer              |
| ------------------------------- | ------------ | ------------------ |
| OpenCTI                         | 8080         | CTI Core           |
| Elasticsearch                   | 9200         | Core               |
| RabbitMQ                        | 5672 / 15672 | Core               |
| MinIO                           | 9000         | Core               |
| RSS Ingestor                    | —            | Pipeline           |
| URLHaus Connector               | —            | Pipeline           |
| NLP Enricher                    | —            | Pipeline           |
| **Intel API (Strategy Engine)** | **8000**     | **Decision Layer** |
| TAXII Server                    | 9000         | Dissemination      |

---

##  Using the Strategic Decision Engine

### Run Daily Strategic Analysis (Manual)

```bash
curl -X POST http://localhost:8000/strategy/run-daily
```

### Run Weekly Strategic Analysis (Manual)

```bash
curl -X POST http://localhost:8000/strategy/run-weekly
```

Generated reports automatically appear in **OpenCTI**.

---

##  Automation & Scheduling

The platform operates fully automatically:

| Task                    | Schedule        |
| ----------------------- | --------------- |
| RSS Collection          | Every 5 minutes |
| NLP Enrichment          | Every 2 minutes |
| URLHaus Import          | Daily           |
| Daily Executive Summary | Daily at 09:00  |
| Weekly Risk Brief       | Monday at 09:00 |

Monitor execution using:

```bash
docker compose logs -f intel-api
```

---



##  Academic & Industry Alignment

This project demonstrates:

* End-to-end CTI lifecycle automation
* Strategic CTI automation
* Decision-focused intelligence analysis
* SOC-aligned architecture
* Practical use of OpenCTI, STIX, and TAXII
* Real-world security automation patterns

It reflects how **modern SOCs and CERT teams** use CTI to support **risk-based decisions**, not just IOC feeds.

---

## 10. Conclusion

This platform shows how Cyber Threat Intelligence can be elevated from **data collection** to **automated security decision-making**.

By integrating collection, enrichment, correlation, and a **Strategic Decision Engine**, the system delivers **actionable intelligence at scale**, suitable for enterprise and national-level security operations.


