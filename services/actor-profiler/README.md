# Honeypot Actor Profiler → OpenCTI Integration

Machine-learning powered pipeline that automatically converts honeypot attack logs into structured cyber threat intelligence in OpenCTI.

It performs:

- Log ingestion from Elasticsearch
- Feature engineering per attacker IP
- ML-based attacker profiling
- Actor clustering
- Automatic Indicator creation in OpenCTI
- Automatic Threat Actor creation
- Automatic relationship linking

---

# Architecture Overview

```
Honeypot Logs
     │
     ▼
Elasticsearch
     │
     ▼
Actor Profiler Service
     │
     ├─ Feature Engineering
     ├─ ML Prediction
     ├─ Actor Clustering
     │
     ▼
OpenCTI
     ├─ Indicators (IP addresses)
     ├─ Threat Actor Groups
     └─ Relationships (Indicator → indicates → Threat Actor)
```

---

# Features

- Fully automated threat actor attribution
- Machine learning based behavioral profiling
- Real-time and batch processing
- Automatic OpenCTI entity creation
- Indicator deduplication
- Actor clustering support
- Continuous monitoring mode
- Restart-safe state handling

---

# Models

Models are loaded automatically from HuggingFace:

```
HF_REPO_ID=muzi5622/actor-profiler-model
```

Repository contains:

```
best_actor_model.joblib
actor_cluster_model.joblib
```

Each model bundle contains:

```
{
    "model": sklearn_model,
    "feature_cols": [...]
}
```

---

# Workflow

## Step 1 — Fetch Logs

Service fetches honeypot logs from Elasticsearch:

Index:

```
honeypot-logs-*
```

Example document:

```json
{
  "@timestamp": "2026-02-26T10:00:00Z",
  "source_ip": "94.231.206.36",
  "protocol": "ssh",
  "destination_port": 22,
  "auth_attempts": [
    {"username": "root", "password": "123456"}
  ]
}
```

Debug example:

```
Fetching ALL historical logs...
Fetched 14382 events
```

---

## Step 2 — Feature Engineering

Features built per source IP:

```
session_count
event_count
total_duration
unique_ports
unique_protocols
auth_event_count
unique_cred_pairs
events_per_session
auth_per_session
duration_per_session
```

Debug example:

```
Built features for 312 IPs
Feature dataframe shape: (312, 10)
```

---

## Step 3 — ML Prediction

Actor classification:

```
pred = model.predict(features)
```

Debug example:

```
Prediction unique values:
['scanner', 'botnet', 'bruteforce']
```

---

## Step 4 — Actor Clustering

Cluster assignment:

```
cluster_ids = cluster_model.predict(features)

clusters = [
  "HP-ACTOR-000",
  "HP-ACTOR-001",
  "HP-ACTOR-002"
]
```

Debug example:

```
Cluster unique values:
[0, 1, 2]
```

---

## Step 5 — Create Indicator in OpenCTI

Indicator created or reused:

Example:

```
IPv4 94.231.206.36
```

Pattern:

```
[ipv4-addr:value = '94.231.206.36']
```

Debug example:

```
Found existing indicator for 94.231.206.36
SUCCESS: Got indicator_id f8d26203-2276-42e0
```

---

## Step 6 — Create Threat Actor Group

Actor created automatically:

Example:

```
HP-ACTOR-002
```

Debug example:

```
Found existing actor: HP-ACTOR-002
```

---

## Step 7 — Create Relationship

Relationship created:

```
Indicator → indicates → Threat Actor
```

Debug example:

```
Created indicates relationship: a19ede21-6a6f
```

---

# Final Result in OpenCTI

OpenCTI will contain:

```
Threat Actor: HP-ACTOR-002

Indicators:
  94.231.206.36
  101.71.37.81
  162.142.125.215

Relationships:
  Indicator → indicates → Threat Actor
```

---

# Labels Applied

Each indicator gets labels:

```
honeypot
actor-profile
<ml-predicted-label>
hp-cluster
HP-ACTOR-XXX
```

---

# Environment Variables

Required:

```
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=your_token

ES_URL=http://elasticsearch:9200
ES_INDEX=honeypot-logs-*

HF_REPO_ID=muzi5622/actor-profiler-model
HF_TOKEN=optional

RUN_EVERY_SECONDS=300

STATE_PATH=/state/state.json
```

---

# Debug Logging (Recommended)

Add debug block:

```python
print("\n===== DEBUG START =====")

print("Total docs:", len(docs))

print("Feature shape:", feat.shape)

print("Unique IPs:", feat["source_ip"].nunique())

print("Prediction unique:", np.unique(pred))

print("Cluster unique:", np.unique(cluster_ids))

print(feat.head())

print("===== DEBUG END =====\n")
```

---

# Demo Example Output

```
Fetching ALL historical logs...

Built features for 312 IPs

Prediction unique values:
['scanner', 'botnet']

Cluster unique values:
[0,1]

Processing IP: 94.231.206.36

Created indicates relationship

Successfully processed
```

---

# Processing Loop

Continuous processing:

```
while True:

    fetch logs

    build features

    run ML prediction

    run clustering

    create indicators

    create actors

    link relationships

    sleep
```

---

# State Handling

State stored in:

```
/state/state.json
```

Ensures restart safety.

---

# Entities Created in OpenCTI

```
Indicator
Threat Actor Group
Relationship
Label
```

---

# Intelligence Generated

Enables:

- Attacker attribution
- Actor infrastructure tracking
- Behavior clustering
- Automated CTI generation

---

# Troubleshooting

## All IPs linked to same actor

Check clustering code:

```
cluster_ids = cluster_model.predict(features)
```

---

## Relationship creation fails

Use relationship:

```
relationship_type="indicates"
```

---

## No features built

Ensure logs contain:

```
source_ip
@timestamp
auth_attempts
```

---

## Model predicts only one class

Check:

```
np.unique(pred)
```

---

# Manual Run

Start service:

```
python actor_profiler.py
```

Expected output:

```
Successfully processed IP
```

---

# Performance

Typical:

```
10k events → < 3 seconds
100k events → < 10 seconds
```

---

# Summary

This system converts honeypot logs into structured threat intelligence automatically using machine learning and OpenCTI integration.

Provides automated:

- attribution
- clustering
- enrichment
- intelligence generation

---

# Future Improvements

- Real-time streaming mode
- Actor naming automation
- Infrastructure entity creation
- Behavior anomaly detection
- Visualization dashboards

---
