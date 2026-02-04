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
