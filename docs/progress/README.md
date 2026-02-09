# SentinelTI Build Log

This document tracks the step-by-step progress of building SentinelTI, a small threat intelligence aggregation tool.

---

## Day 1 – Project setup & environment

**What I did**

- Created the `SentinelTi` project folder and Python package structure.
- Set up a Python virtual environment (`.venv`) for isolated dependencies.
- Added `requirements.txt` and installed core libraries (`requests`, etc.).
- Created `config.py` for basic settings and `db.py` for database initialization.
- Implemented a simple CLI using `argparse` with an `init` command to create the SQLite database.

**Screenshot**

![alt text](<Screenshot 2026-02-02 234806.png>)
---

## Day 2 – URLhaus feed ingestion

**What I did**

- Designed a SQLite schema with `feeds` and `indicators` tables to store threat intelligence data.
- Implemented `init_db()` in `db.py` to create tables on demand.
- Wrote `feeds/urlhaus.py` to:
  - Download the recent URLhaus CSV feed from abuse.ch.
  - Parse the CSV, extract malicious URLs and metadata (date, threat type, tags).
  - Insert or update indicators in the `indicators` table with first/last seen timestamps.
- Extended the CLI with an `ingest` command:
  - `python -m sentinelti.cli ingest urlhaus` ingests recent malicious URLs into the database.

**Screenshots**

[alt text](<Screenshot 2026-02-02 235031.png>)

![alt text](<Screenshot 2026-02-02 235331.png>)

# Day 3 – Threat Intel + ML URL Classifier


### ML Module Layout

- Created new package: `sentinelti/ml/`
  - `__init__.py`
  - `features.py`
  - `dataset.py`
  - `train.py`
  - `predict.py`

This sets up a clear pipeline: feature extraction → dataset → training → prediction.

---

### URL Feature Extraction

- Implemented `extract_features(url: str)` in `sentinelti/ml/features.py`.
- Extracted lexical features commonly used in malicious URL detection:
  - URL/domain/path/query lengths
  - Counts of digits, letters, special characters
  - Ratios (digits/letters per URL length)
  - Structural features (IP-like host, dot and hyphen counts, path segments, query params)
  - Suspicious keyword hits (`login`, `verify`, `update`, `secure`, `account`, etc.)
  - Raw TLD captured for future encoding

- Verified behavior by running:

  ```bash
  python -c "from sentinelti.ml.features import extract_features; print(extract_features('http://example.com/login?user=1'))"

![alt text](<Screenshot 2026-02-03 125702.png>)

- Build dummy dataset in dataset.py for demo
turning the feature dicts into a numeric matrix X and label vector y,
![alt text](<Screenshot 2026-02-03 132228.png>)

- Implement the train_url_model
    train_test_split gives a small test set to evaluate the model.

    classification_report prints precision/recall/F1 for each class so we can see how well the dummy model does.

    We save both the model and feature_names so prediction uses the same feature order later.
![alt text](<Screenshot 2026-02-03 133338.png>)

- Implement the predict_url
![alt text](<Screenshot 2026-02-03 133957.png>)

---Day 3: Get real dataset + training -> real TI URL classifier

- Added "Malicious and Benign URLS" dataset from Kaggle
![alt text](<Screenshot 2026-02-04 132347.png>)

- Added and updated the dataset.py with build_real_dataset function
![alt text](<Screenshot 2026-02-04 164419.png>)

- Updated train.py with adding build_real_dataset import and tried changing max_sample limit for troubleshooting
![alt text](<Screenshot 2026-02-04 164823.png>)

- Updated predict.py with higher threshold 0.5 -> 0.9
![alt text](<Screenshot 2026-02-04 164929.png>)

- Day log:
We’ve basically taken SentinelTI from “toy ML” to a first real URL classifier. Here’s the short story, in order:

### 1. Started with a dummy model

- You had a small hard-coded list of benign and malicious-looking URLs in `build_dummy_dataset`, which:
  - Generated lexical features for each URL.
  - Produced `X` (feature matrix), `y` (0/1 labels), and `feature_names`.  
- `train.py` used only this dummy dataset:
  - Split into train/test.
  - Trained a `LogisticRegression` model.
  - Printed a classification report.
  - Saved the model artifact (model + feature names) with `joblib`.

This gave you a working training pipeline, but on tiny synthetic data.

### 2. Added a real CSV-based dataset builder

- You extended `dataset.py` with `build_real_dataset(csv_path, ...)`, which:
  - Loads a labeled CSV (`urldata.csv`) with at least `url` and `label` columns.  
  - Filters rows to the allowed labels (benign vs malicious).  
  - Optionally samples up to `max_samples`.  
  - Uses the same feature extraction as the dummy builder to create `X`, `y`, and `feature_names`.

- You also fixed the structure so:
  - Label filtering happens before sampling.
  - The function raises a clear error if no rows match the expected labels.

### 3. Updated `train_url_model` to support real data

- In `train.py`, you changed `train_url_model` to accept:

  ```python
  def train_url_model(
      use_real_data: bool = False,
      csv_path: str | None = None,
      max_samples: int | None = None,
  )
  ```

- Logic:
  - If `use_real_data=True`, call `build_real_dataset(...)` with the CSV path and label mapping.
  - Otherwise, fall back to `build_dummy_dataset`.

- You kept the same ML steps:
  - `train_test_split` with stratification.
  - Train logistic regression.
  - Print classification report.
  - Save `{ "model": clf, "feature_names": feature_names }` to `url_classifier.joblib`.

- In the `if __name__ == "__main__":` block you configured:

  ```python
  train_url_model(
      use_real_data=True,
      csv_path="data/urldata.csv",
      max_samples=1000,
  )
  ```

### 4. Fixed early issues with tiny test sets

- At first, you effectively ended up with a very small number of samples in the test split, which produced:
  - Only 3 test samples.
  - Warnings about undefined precision for the minority class (no predicted positives).

- We diagnosed that:
  - The dataset in use was too small (or over-sampled down).
  - `build_real_dataset` needed a clean filter and proper empty-check.

- After fixing and letting it use 1,000 rows, the classification report became:

  - 779 benign, 221 malicious in total.
  - On the 300-sample test set:
    - Benign: F1 ≈ 0.99
    - Malicious: F1 ≈ 0.94
    - Overall accuracy ≈ 0.98

So, the model is performing very well on that dataset.

### 5. Implemented and tuned `predict_url`

- You already had `predict_url(url)` which:
  - Loads the saved model + feature names.
  - Extracts features for a single URL.
  - Uses `predict_proba` to get the probability of class 1 (malicious).
  - Returns `(label, prob_malicious)` where `label = int(prob_malicious >= 0.5)`.

- When we tested on real-world benign URLs (`google.com`, `microsoft.com`, etc.), the model gave:
  - Malicious label (1) with ~0.76 probability for several big-brand domains.
  - Benign label (0) with low malicious probability for `nytimes.com`.
  - An obvious phish got label 1 with probability ~0.99999.

- This told us:
  - The model and code were correct, but the threshold 0.5 was too aggressive for your use case.
  - Lexical URL features alone can misjudge some benign big-name domains.

- To reduce false positives for benign URLs, you:
  - Introduced a higher malicious threshold (e.g., 0.9) inside `predict_url`:

    ```python
    MALICIOUS_THRESHOLD = 0.9
    label = int(prob_malicious >= MALICIOUS_THRESHOLD)
    ```

  - Re-ran tests:
    - Big-brand URLs: now label 0, with malicious probabilities still ~0.76 (visible as a “risk score” but not auto-blocking).
    - Obvious phish: still label 1 with probability ~1.0.



## 2026-02-05 – Day Progress (Threat-Intel URL Classifier + ML)

**1. Integrated URLhaus-backed malicious data**

- Implemented a new helper module to load malicious URLs directly from the existing SQLite threat-intel database (URLhaus feed already ingested into `feeds` and `indicators` tables).  
- The helper queries `indicators` for `type='url'` and the `urlhaus` feed, returns a DataFrame with `url` and `label="malicious"`.  
- Added basic validation: raises an error if no URLhaus indicators are found.

![alt text](<Screenshot 2026-02-05 130003.png>)

***

**2. Built combined URLhaus + benign dataset builder**

- Extended the dataset layer with a new function to:
  - Load malicious URLs from the URLhaus-backed DB helper.  
  - Load benign URLs from the existing `data/urldata.csv` (filtering on `label="benign"`).  
  - Optionally subsample both sides (max malicious, max benign) for balanced training size.  
- Normalized both sources to a unified schema (`url`, `label`), mapped labels to `0 = benign`, `1 = malicious`.  
- Reused the existing URL feature extractor to build `X` (feature matrix), `y` (labels), and `feature_names`.

![alt text](<Screenshot 2026-02-05 130053.png>)

***

**3. Extended training pipeline to support URLhaus mode**

- Updated the training script to support a new mode:  
  - `use_urlhaus=True` → trains on “URLhaus malicious + benign CSV”, instead of only `urldata.csv` or dummy data.  
- Training flow:
  - Build combined dataset via the new builder.  
  - Stratified train/test split (70/30).  
  - Train logistic regression with `max_iter=1000`.  
  - Print classification report and save model artifact (`url_classifier.joblib` with model + feature names).

![alt text](<Screenshot 2026-02-05 130157.png>)

***

**4. Ran URLhaus ingestion and trained the new model**

- Installed the missing HTTP client library and successfully ran the URLhaus ingestion job to populate the local DB with recent URLhaus indicators.  
- Executed the updated training entrypoint in URLhaus mode.  
- Observed excellent evaluation metrics on the holdout set (balanced benign/malicious sample):
  - Precision, recall, and F1 for both benign and malicious ≈ 0.99.  
  - Overall accuracy ≈ 0.99, confirming the combined dataset and pipeline are working well.

![alt text](<Screenshot 2026-02-05 130157-1.png>)

***

**5. Evaluated and tuned prediction behavior**

- Re-ran `predict_url` on a mix of real-world benign and phishy URLs (Google, Microsoft, Apple, GitHub, NYTimes, and an obvious phishing-style URL).  
- Confirmed:
  - Phishing-style URL receives the highest malicious probability.  
  - Clearly benign site (NYTimes) has a very low malicious probability.  
  - Big-brand homepages sit in a mid-to-high probability band, close to the phishing URL, revealing that the model’s scores are well ranked but tightly clustered.  
- Experimented with different decision thresholds for labeling (0/1) and concluded:
  - The model and prediction code are correct.  
  - With the current dataset size and feature set, predictions are generally good but not perfectly calibrated; threshold choice is an explicit trade-off between catching phish and avoiding false positives on some benign big-brand domains.

![alt text](<Screenshot 2026-02-05 130330.png>)

***

**Summary for today**

- Moved from a generic CSV-trained model to a **Threat-Intel-driven model** that uses URLhaus data via the project’s own TI database.  
- Established a reusable path from **URLhaus → DB → combined dataset → trained model → `predict_url`**, with strong test metrics and initial threshold tuning.

---Log: 02/08/2026

## Environment and Setup

- Repaired Python installation on Windows and ensured system uses Python 3.11.  
- Recreated clean virtual environment (`.venv`) and reinstalled dependencies from `requirements.txt`.  
- Verified database initialization and URLhaus ingestion complete successfully.  
![alt text](<Screenshot 2026-02-08 123523.png>)

***

## Model Training and Baseline Results

- Trained URL classification model on ingested URLhaus data.  
- Achieved ~99% accuracy, precision, and recall on a 600‑sample holdout set (balanced benign/malicious).  
- Saved trained model to `sentinelti/models/url_classifier.joblib`.  

![alt text](<Screenshot 2026-02-08 123623.png>)

***

## CLI Scoring and Sanity Checks

- Confirmed `score-url` and `score-urls` commands work end‑to‑end.  
- Tested with clearly benign URLs (Google, Microsoft, BBC) and clearly malicious / phishing‑style URLs.  
- Observed sensible `label` and `prob_malicious` outputs for basic cases.  

![alt text](<Screenshot 2026-02-08 123656.png>)

***

## Heuristic Risk Layer on Top of ML

- Implemented `enrich_score()` helper to wrap `score_url` results.  
- Added heuristic features:
  - Detection of `@` in authority part (obfuscation).  
  - Raw IP hosts.  
  - Suspicious tokens (e.g., `login`, `verify`, `update`, `account`, `paypal`, `bank`, `appleid`).  
  - Uncommon TLDs (e.g., `.xyz`, `.top`, `.club`, `.click`, `.link`).  
- Introduced `final_label` (`benign`, `suspicious`, `malicious`) and `risk` (`low`, `medium`, `high`) in CLI output.  
- Example: `http://update-paypal.com@evil.com/secure` now returns `final_label='suspicious'` with clear reasons.  

![alt text](<Screenshot 2026-02-08 123849.png>)

***

## Dependency and Test Improvements

- Added `tldextract` to `requirements.txt` for URL parsing and TLD handling.  
- Created `tests/test_ml_service.py` with basic unit tests for:
  - `score_url` – structure and types of returned dict.  
  - `score_urls` – correct result count for batch input.  
- Installed `pytest` in the venv and successfully ran the tests via `python -m pytest`.  

***

## Progress log – 2026‑02‑09

Today was focused on turning SentinelTi’s URL scoring into a clean, reusable core and making the CLI output more script‑ and API‑friendly.

***

### 1. Added a dedicated heuristic analysis module

**What I did**

- Created `sentinelti/heuristics.py`.
- Implemented `analyze_url(url)` which:
  - Parses the URL (host, path, query, TLD).
  - Applies several heuristic rules:
    - Raw IP address as host.
    - `@` in the authority part.
    - Suspicious tokens in the path/query (e.g. `login`, `verify`, `payment`, `account`, `paypal`, `appleid`, etc.).
    - Uncommon TLDs (e.g. `.xyz`, `.top`, `.club`, `.click`, `.link`, etc.).
    - Very long domain (subdomain + domain).
    - Deep path (many path segments).
  - For each rule that fires, increases a numeric heuristic score and adds a human‑readable reason.
  - Returns a `HeuristicResult` with:
    - `score` (float),
    - `reasons` (list of explanation strings),
    - `features` (small dict with `tld`, `domain_length`, `path_depth`, `raw_score`).

**Why / purpose**

- Gives SentinelTi a rule‑based “gut check” layer in addition to the ML model.
- Makes results more explainable: we can say *why* a URL looks risky.
- Keeps heuristic logic isolated and testable, instead of scattering it in the CLI.

![alt text](<Screenshot 2026-02-09 151356.png>)

***

### 2. Added a central scoring/enrichment module

**What I did**

- Created `sentinelti/scoring.py`.
- Implemented `enrich_score(url)` which:
  - Calls the existing ML service (e.g. `ml.service.score_url(url)`) to get:
    - `url`, `label`, `prob_malicious`.
  - Calls `analyze_url(url)` to get heuristic `score`, `reasons`, and `features`.
  - Combines ML probability and heuristic score with simple thresholds to decide:
    - `final_label`: `"benign"`, `"suspicious"`, or `"malicious"`.
    - `risk`: `"low"`, `"medium"`, or `"high"`.
  - Ensures `reasons` is populated:
    - Uses heuristic reasons when present.
    - Falls back to generic messages like “Flagged primarily by the ML classifier score.” when needed.
  - Returns a single enriched dict containing:
    - `url`, `label`, `prob_malicious`,
    - `heuristic` (nested dict with score/reasons/features),
    - `final_label`, `risk`, and top‑level `reasons`.

**Why / purpose**

- Creates one **single source of truth** for “how SentinelTi scores a URL”.
- Separates concerns:
  - ML model serving (`ml.service`) stays model‑focused.
  - Heuristics stay in `heuristics.py`.
  - Combination and decisions live in `scoring.py`.
- Makes it easy for the CLI, tests, and future FastAPI API to all use the same scoring logic.

![alt text](<Screenshot 2026-02-09 151758.png>)

***

### 3. Refactored the CLI to use the central scoring

**What we did**

- Updated `sentinelti/cli.py`:
  - Removed inline heuristic logic and the old CLI‑local `enrich_score(url, score_result)` function.
  - Stopped importing URL parsing/heuristics directly in the CLI.
  - Imported and used the shared `enrich_score(url)` instead.
- Now:
  - `score-url`:
    - Calls `enrich_score(args.url)`.
    - Prints the enriched result.
  - `score-urls`:
    - Loops over `args.urls`, calls `enrich_score(url)` for each.
    - Prints each enriched result.

**Why / purpose**

- Makes the CLI a **thin wrapper** around the core scoring logic.
- Guarantees that CLI and future API will always use the exact same scoring and heuristics.
- Simplifies future changes: tuning thresholds or adding new heuristics only requires updating `heuristics.py` / `scoring.py`, not the CLI.

![alt text](<Screenshot 2026-02-09 151954.png>)

***

### 4. Added JSON and pretty‑JSON output to the CLI

**What we did**

- Extended `score-url` to accept:
  - `--json`: output the enriched result as a compact JSON object.
  - `--json-pretty`: output the same JSON but nicely formatted with indentation.
- Extended `score-urls` to accept:
  - `--json`: output a JSON array of enriched results.
  - `--json-pretty`: pretty‑print that array.
- Under the hood:
  - Uses `json.dumps(result, indent=None)` for `--json`.
  - Uses `json.dumps(result, indent=2)` for `--json-pretty`.

**Why / purpose**

- Makes SentinelTi much easier to integrate into scripts and other tools:
  - You can pipe CLI output into `jq`, log pipelines, or custom scripts without parsing Python dicts.
- Aligns with how the future FastAPI endpoints will behave (they will also speak JSON).
- Improves usability when inspecting results manually (`--json-pretty` is much easier to read).

![alt text](<Screenshot 2026-02-09 152100.png>)
***

### 5. Added a basic unit test for the enriched scoring

**What we did**

- Created `tests/test_scoring.py` with a simple test:
  - Calls `enrich_score("http://example.com")`.
  - Asserts that keys like `url`, `label`, `prob_malicious`, `final_label`, `risk`, `reasons`, and `heuristic` are present.
  - Checks that `reasons` is a list and `heuristic` is a dict.
- Ran `python -m pytest` and confirmed all tests pass (including the existing ML service tests).

**Why / purpose**

- Ensures the new central scoring function is covered by tests.
- Gives an early warning if the structure of the enriched result changes unexpectedly.
- Helps keep the public output contract stable as the project grows.

![alt text](<Screenshot 2026-02-09 152409.png>)

***

Overall, today’s work:

- Centralized the “intelligence” of SentinelTi into `heuristics.py` and `scoring.py`.
- Turned the CLI into a thin, reusable front‑end.
- Added JSON output so SentinelTi is ready for automation and a future HTTP API.