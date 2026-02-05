## 🧠 ML-NER Enricher (Hugging Face Model Integration)

### What this feature adds

This platform now includes an **ML-powered NER Enricher** that uses a **Transformer model hosted on Hugging Face**:

* Model: `muzi5622/cti-ner-model`
* Task: Token classification (NER) for CTI text
* Output: Extracted IOCs + entity hints → **OpenCTI observables + labels + report linking**

The service runs automatically and continuously:

1. Pulls latest **Reports** from OpenCTI
2. Extracts IOCs from report title + description
3. Creates STIX **Cyber Observables** (Url, Domain-Name, IPv4-Addr, StixFile)
4. Adds labels like:

   * `enriched:ml-ner`
   * `ml:url`, `ml:domain`, etc.
5. Links created observables to the report via:

   * `relationship_type: "object"`

---

## Why Hugging Face model loading matters

Instead of shipping the model files inside the repo/container, the service loads directly from Hugging Face:

```python
MODEL_PATH = os.getenv("MODEL_PATH", "muzi5622/cti-ner-model").strip()
```

### Benefits

* Easier updates (push new model → service can use it)
* Smaller repo size
* Cleaner CI/CD

### Requirements

* Container must have internet access (unless running in offline mode)
* If repo is private/gated → token is required

---

## Configuration

### Environment Variables

| Variable                             | Purpose                                   | Default                  |
| ------------------------------------ | ----------------------------------------- | ------------------------ |
| `MODEL_PATH`                         | Hugging Face repo id OR local folder path | `muzi5622/cti-ner-model` |
| `HF_TOKEN` / `HUGGINGFACE_HUB_TOKEN` | Needed only if model is private           | *(empty)*                |
| `NER_THRESHOLD`                      | Confidence threshold                      | `0.55`                   |
| `POLL_SECONDS`                       | Poll interval                             | `60`                     |
| `LOOKBACK_HOURS`                     | Reports lookback window                   | `24`                     |
| `CREATE_OBSERVABLES`                 | Enable observable creation                | `true`                   |
| `STATE_PATH`                         | Report processing state file              | `/data/state.json`       |

### Recommended Docker cache

To avoid downloading the model on every restart, mount HF cache:

* `/root/.cache/huggingface`

---

## Common Debug Issues (and fixes)

### ✅ 1) `401 Unauthorized` from Hugging Face

**Cause:** model is private/gated and container is not logged in.
**Fix:** set token in docker-compose:

* `HF_TOKEN=xxxxx`

---

### ✅ 2) `DistilBert... unexpected keyword argument token_type_ids`

**Cause:** DistilBERT does not accept `token_type_ids`.
**Fix:** the enricher patches model forward to drop `token_type_ids` automatically.

---

### ✅ 3) Report linking fails with `relationship type not supported`

**Cause:** OpenCTI doesn’t accept `related-to` for report ↔ observable.
**Fix:** we use supported relationship type:

* `object`

---

### ✅ 4) `report(id:ID!)` vs `report(id:String!)`

Your OpenCTI schema expects:

* `report(id: String!)` for queries
* `reportEdit(id: ID!)` for mutations

The service uses the correct types.

---

## How to Verify It’s Working

### 1) Verify service logs

Run:

```bash
docker compose logs -f ml-ner-enricher
```

You should see cycles like:

* `cycle done new=X processed_total=Y`

---

### 2) Verify ML-created observables exist

Query OpenCTI for observables labeled `enriched:ml-ner`:

```bash
curl -sS http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENCTI_ADMIN_TOKEN" \
  -d '{
    "query":"query($first:Int!,$filters:FilterGroup){ stixCyberObservables(first:$first, filters:$filters, orderBy:created_at, orderMode:desc){ edges{ node{ id entity_type created_at ... on StixCyberObservable{ observable_value } objectLabel{ value } } } } }",
    "variables":{
      "first":50,
      "filters":{
        "mode":"and",
        "filters":[{"key":"objectLabel","values":["enriched:ml-ner"],"operator":"eq"}],
        "filterGroups":[]
      }
    }
  }'
```

If you see results → ML observable creation is working.

---

### 3) Verify report linking works (GUI)

In OpenCTI UI:

1. Go to **Reports**
2. Open the report you want
3. Click **Objects**
4. You should see linked observables (URLs/domains/IPs/hashes)

---

### 4) Verify in OpenCTI UI (Observables list)

1. Go to **Observables**
2. In filter/search: use label **`enriched:ml-ner`**
3. You’ll see entries created by the ML enricher
4. Open any observable and confirm labels include:

   * `enriched:ml-ner`
   * `ml:*`

---

## ML vs Rule-Based NLP (what’s the difference?)

### Existing NLP enricher

* Mainly regex rules
* Very fast and deterministic
* Extracts “obvious” indicators

### ML-NER enricher

* Uses Transformer model (context-aware)
* Adds **intelligence enrichment tags** (`ml:*`)
* Adds a clean audit trail (`enriched:ml-ner`)
* Can be improved by retraining on CTI datasets

They are complementary:

* NLP = baseline reliable extraction
* ML = smarter enrichment and future extensibility

---

## Next Improvements (Optional)

* Create Vulnerability objects for CVEs (vulnerabilityAdd)
* Add report labels (if label mutations are available)
* Expand entity mapping (Malware / Threat Actor) into OpenCTI entities

---
