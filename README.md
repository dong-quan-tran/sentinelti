# SentinelTi

SentinelTi is a Python‑based malicious URL detection tool. It ingests threat intel feeds (currently URLhaus), stores indicators in SQLite, and scores URLs using a combination of a trained ML model and heuristic rules. The tool exposes a CLI that can classify single or multiple URLs and output human‑readable or JSON results.

***

## Requirements

- Python 3.11
- Git
- Windows (current dev environment; should be portable to other OSes with minor tweaks)

Python dependencies are listed in `requirements.txt` and installed into a virtual environment.

***

## Setup and installation

1. **Clone the repository**

```bash
git clone https://github.com/dong-quan-tran/SentinelTi.git
cd SentinelTi
```

2. **Create a virtual environment**

On Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

On Windows (cmd):

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

Your prompt should now show `(.venv)`.

3. **Install dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

***

## Running tests

From the project root with the venv activated:

```bash
python -m pytest
```

This runs the existing test suite, including tests for the ML scoring service and the enriched scoring logic.

***

## Database initialization and feed ingestion

SentinelTi uses a local SQLite database to store indicators from URLhaus.

1. **Initialize the database**

```bash
python -m sentinelti.cli init
```

2. **Ingest URLhaus feed**

```bash
python -m sentinelti.cli ingest urlhaus
```

This downloads the recent URLhaus feed and upserts indicators into the local database.

***

## Scoring URLs from the CLI

SentinelTi exposes CLI commands to score URLs using the ML model plus heuristic enrichment.

### Score a single URL

Human‑readable output:

```bash
python -m sentinelti.cli score-url "http://example.com"
```

JSON output:

```bash
python -m sentinelti.cli score-url "http://example.com" --json
python -m sentinelti.cli score-url "http://example.com" --json-pretty
```

The enriched result includes:

- `url`
- `label` (raw ML label)
- `prob_malicious` (model probability)
- `heuristic` (score, reasons, features)
- `final_label` (`benign` / `suspicious` / `malicious`)
- `risk` (`low` / `medium` / `high`)
- `reasons` (human‑readable explanations)

### Score multiple URLs

Human‑readable output:

```bash
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login"
```

JSON output:

```bash
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login" --json
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login" --json-pretty
```

This returns a list of enriched results, one per URL.

***

## Project structure (high level)

- `sentinelti/`
  - `cli.py` – command‑line interface (init, ingest, score‑url, score‑urls).
  - `heuristics.py` – rule‑based URL analysis (IP hosts, suspicious tokens, TLDs, etc.).
  - `scoring.py` – central `enrich_score(url)` that combines ML and heuristics into a final result.
  - `ml/` – ML model loading and `score_url()` service.
  - `db.py` – SQLite initialization and connection logic.
  - `feeds/urlhaus.py` – URLhaus ingestion utilities.
- `tests/` – pytest test suite.
- `docs/` – progress logs, design notes, and screenshots.

***



## How it works (high level)

SentinelTi combines a trained ML classifier with rule‑based heuristics to decide whether a URL is benign, suspicious, or malicious.

1. **Threat intel ingestion (URLhaus)**  
   - SentinelTi ingests recent malicious URL data from the URLhaus feed and stores it in a local SQLite database.  
   - The database tracks feeds and indicators (URLs, timestamps, tags, etc.), which can be used for model training, updating, and analysis.

2. **Machine learning URL classifier**  
   - A Python‑based ML model is trained to classify URLs as benign or malicious.  
   - The model is saved to disk (e.g. `sentinelti/models/url_classifier.joblib`) and loaded by a small service layer.  
   - The ML service exposes a simple `score_url(url)` function that returns:
     - `url`
     - `label` (model’s prediction)
     - `prob_malicious` (probability the URL is malicious)

3. **Heuristic analysis layer**  
   - On top of the ML model, SentinelTi applies hand‑crafted heuristics that look for patterns commonly seen in phishing and malware URLs, such as:
     - Raw IP addresses used as hosts.
     - `@` in the authority part of the URL (obfuscation trick).
     - Suspicious tokens in the path/query (`login`, `verify`, `account`, `paypal`, `payment`, etc.).
     - Uncommon or abuse‑heavy TLDs (e.g. `.xyz`, `.top`, `.club`, `.click`).
     - Unusually long domains or deep paths.  
   - Each heuristic contributes to a numeric heuristic score and a list of human‑readable reasons explaining why the URL looks risky.

4. **Central scoring and enrichment**  
   - A central function (`enrich_score(url)`) combines:
     - ML output (`label`, `prob_malicious`),
     - heuristic score and reasons.  
   - It then derives:
     - `final_label`: `"benign"`, `"suspicious"`, or `"malicious"`,
     - `risk`: `"low"`, `"medium"`, or `"high"`,
     - a unified list of `reasons` suitable for CLI/API responses.  
   - This enriched result is the single source of truth used by the CLI and, later, the HTTP API.

5. **Interfaces (CLI and future API)**  
   - **CLI**:
     - Initialize the DB: `python -m sentinelti.cli init`
     - Ingest URLhaus feed: `python -m sentinelti.cli ingest urlhaus`
     - Score URLs:
       - Single: `python -m sentinelti.cli score-url "<url>"`
       - Multiple: `python -m sentinelti.cli score-urls "<url1>" "<url2>" ...`
     - All scoring commands can output either:
       - Human‑readable Python dicts, or
       - Machine‑readable JSON (`--json` / `--json-pretty`) for integration in scripts and future services.  
   - **Planned FastAPI HTTP API**:
     - Reuse the same `enrich_score(url)` function.
     - Expose endpoints like `/health`, `/score-url`, and `/score-urls` for programmatic access.


***

## Training the URL classifier

SentinelTi ships with a small ML pipeline under `sentinelti/ml/` that trains a URL
classifier from either the Kaggle dataset or a combination of URLhaus + benign URLs.

### Prerequisites

- Dependencies installed:

  ```bash
  pip install -r requirements.txt
  ```

- A labeled URL CSV (e.g. Kaggle “malicious and benign URLs”) placed at:

  ```text
  data/urldata.csv
  ```

  Required columns:

  - `url`
  - `label` with values `benign` or `malicious`

### CLI usage

Training is controlled via `--model` and `--source` flags:

- Train **XGBoost** on Kaggle:

  ```bash
  python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
  ```

- Train **Logistic Regression** on Kaggle:

  ```bash
  python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
  ```

- Train **XGBoost** on URLhaus malicious + Kaggle benign:

  ```bash
  python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
  ```

- Use the small built‑in dummy dataset (for quick tests):

  ```bash
  python -m sentinelti.ml.train --model logreg --source dummy
  ```

Model artifacts are saved to:

```text
sentinelti/models/url_classifier.joblib
```

and are loaded by the SentinelTi ML scoring service (`score_url`) and the
central `enrich_score(url)` logic.
```

In short, SentinelTi ingests real threat intel, uses an ML model for core classification, enhances it with explainable heuristics, and exposes the combined result via a clean CLI (and soon an HTTP API).