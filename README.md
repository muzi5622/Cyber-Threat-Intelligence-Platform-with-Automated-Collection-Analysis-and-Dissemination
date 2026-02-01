# CTI Platform (EduQual Level 6)

## Automated Cyber Threat Intelligence: Collection → Analysis → Dissemination

**Project Title:**
Comprehensive Cyber Threat Intelligence Platform with Automated Collection, Analysis, and Dissemination

**Student:** Muzammal

**Qualification:** Diploma in Artificial Intelligence Operations (EduQual Level 6)

**Core Technologies:**
OpenCTI · OSINT (RSS + SpiderFoot) · NLP/IOC Extraction · STIX 2.1 · TAXII-style Sharing · Docker

---

## 1. Project Overview

This project implements a **fully automated Cyber Threat Intelligence (CTI) platform** that follows the complete intelligence lifecycle used by real Security Operations Centers (SOCs), MSSPs, and national CERT teams.

The platform continuously:

1. **Collects** threat intelligence from open-source feeds
2. **Analyzes and enriches** intelligence using NLP and OSINT automation
3. **Stores and correlates** intelligence in OpenCTI
4. **Disseminates** intelligence using STIX 2.1 via a TAXII-style interface

All components run automatically using Docker Compose and communicate via APIs and message queues.

---

## 2. End-to-End Automated Flow

```
RSS Feeds ─┐
           ├─> OpenCTI Reports
SpiderFoot ┘        ↓
                 NLP Enricher
                    ↓
        Observables + Indicators
                    ↓
        SpiderFoot Automated Enrichment
                    ↓
              Correlated CTI
                    ↓
          STIX 2.1 Bundle Export
                    ↓
          TAXII-style Distribution
```

---

## 3. Architecture Overview (Layered)

The system is intentionally layered to reflect **industry CTI architectures**.

---

![architecture digram](architecture.png)


### 🔹 Layer 1 – OSINT Collection

**RSS Ingestor (Custom – Fully Automated)**

* Reads 23 curated CTI RSS feeds
* Converts articles into **OpenCTI Reports**
* Uses SQLite state tracking to prevent duplicates

**SpiderFoot (Analyst OSINT Mode)**

* Web-based OSINT reconnaissance tool
* Used for manual or ad-hoc investigation
* Supports deep OSINT research on domains, IPs, URLs

> This layer represents **human-in-the-loop intelligence collection**, which is standard in SOC environments.

---

### 🔹 Layer 2 – CTI Knowledge Base

**OpenCTI Platform**

* Central CTI repository and analyst dashboard
* Stores reports, observables, indicators, and relationships
* Exposes a GraphQL API for automation

**OpenCTI Worker**

* Handles background processing, indexing, and connectors

---

### 🔹 Layer 3 – Core Dependencies

| Service       | Purpose                          |
| ------------- | -------------------------------- |
| Redis         | Cache and internal OpenCTI state |
| Elasticsearch | Indexing and search backend      |
| RabbitMQ      | Asynchronous task queue          |
| MinIO         | Object storage for OpenCTI       |

---

### 🔹 Layer 4 – Analysis & Enrichment (AI + OSINT Automation)

This layer is responsible for **machine-driven intelligence enrichment**.

#### 1. NLP Enricher (Custom – Automated)

* Reads recent OpenCTI reports
* Extracts:

  * Domains
  * URLs
  * IPv4 / IPv6
  * Hashes (MD5 / SHA1 / SHA256)
  * CVEs
* Creates:

  * STIX Observables
  * STIX Indicators (`createIndicator=true`)
* Applies confidence scores and labels (`auto-extracted`)

#### 2. SpiderFoot Automation (Custom – Automated)

SpiderFoot is reused here as an **automated enrichment engine**, not a UI tool.

**Automated Flow:**

```
OpenCTI Reports
   ↓
Extract domains / IPs
   ↓
Trigger SpiderFoot scans
   ↓
Parse OSINT results
   ↓
Push enrichment back to OpenCTI
```

**Key Characteristics:**

* Runs every 600 seconds
* Passive OSINT only (ethical & non-intrusive)
* Uses selected modules:

  * DNS resolution
  * SSL certificate analysis
  * WHOIS
  * Hosting identification
  * Web server fingerprinting
* Converts results into OpenCTI observables and relationships

> This design mirrors commercial CTI enrichment engines (MISP, Anomali, Recorded Future).

---

### 🔹 Layer 5 – Dissemination & Sharing

**TAXII Exporter (Custom)**

* Exports intelligence from OpenCTI into STIX 2.1 JSON bundles

**TAXII Demo Server**

* Serves the STIX bundle via HTTP
* Simulates organizational CTI sharing

---

## 4. Docker Services Summary

| Service               | Port         | Layer        |
| --------------------- | ------------ | ------------ |
| OpenCTI               | 8080         | CTI Platform |
| Elasticsearch         | 9200         | Core         |
| RabbitMQ              | 5672 / 15672 | Core         |
| MinIO                 | 9001         | Core         |
| SpiderFoot            | 5001         | Layer 1      |
| SpiderFoot (nginx)    | 5002         | Layer 1      |
| NLP Enricher          | —            | Layer 4      |
| SpiderFoot Automation | —            | Layer 4      |
| TAXII Server          | 9000         | Layer 5      |
| Intel API             | 8000         | Layer 5      |

---

## 5. Folder Structure

```
cti-platform/
├─ docker-compose.yml
├─ .env
├─ data/
│  ├─ rss/
│  ├─ nlp/
│  ├─ spiderfoot-automation/
│  └─ opencti-export/
└─ services/
   ├─ rss-ingestor/
   ├─ nlp-enricher/
   ├─ spiderfoot-automation/
   ├─ intel-api/
   ├─ taxii-exporter/
   └─ spiderfoot-web/
```

---

## 6. Requirements

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

## 7. Environment Configuration

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

## 9. Access URLs

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

## 10. Automation Verification (Evidence)

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

## 11. Stop and Reset

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

## 12. Academic & Industry Alignment

This project demonstrates:

* End-to-end CTI lifecycle automation
* AI-assisted intelligence analysis
* OSINT enrichment at scale
* STIX/TAXII-compliant intelligence sharing
* Real SOC-style architecture

It aligns with professional roles such as:

* CTI Analyst
* SOC Analyst
* Threat Researcher
* Security Automation Engineer

---

## 13. Key Design Justification

> SpiderFoot is intentionally deployed both as an analyst-driven OSINT tool (Layer 1) and as a fully automated enrichment engine (Layer 4), reflecting real-world CTI operational models.
