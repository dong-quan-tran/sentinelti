"""
Manual evaluation runner for SentinelTi.

Loads docs/manual_eval_urls.csv, runs enrich_score on each URL,
and prints basic confusion counts + sample disagreements.
"""

from __future__ import annotations

import csv
from pathlib import Path
from collections import Counter

from .scoring import enrich_score


def main() -> None:
    # repo root = sentinelti/.. (adjust if your structure differs)
    root = Path(__file__).resolve().parents[1]
    eval_path = root / "docs" / "manual_eval_urls.csv"

    if not eval_path.exists():
        raise SystemExit(f"Manual eval file not found: {eval_path}")

    rows = []
    with eval_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            label = row.get("label", "").strip()
            if not url or not label:
                continue
            rows.append(row)

    results = []
    for row in rows:
        url = row["url"].strip()
        true_label = row["label"].strip()
        notes = row.get("notes", "").strip()
        r = enrich_score(url)
        results.append((url, true_label, notes, r))

    # Confusion on final_label
    counts = Counter()
    for _, true_label, _, r in results:
        pred = r["final_label"]
        counts[(true_label, pred)] += 1

    print("Confusion (true_label -> final_label):")
    for (true_label, pred), c in sorted(counts.items()):
        print(f"  {true_label:10s} -> {pred:10s}: {c}")

    print("\nSample disagreements:")
    for url, true_label, notes, r in results:
        if true_label != r["final_label"]:
            print(f"- URL:        {url}")
            print(f"  true_label: {true_label}")
            print(f"  final_label:{r['final_label']}")
            print(f"  risk:       {r['risk']}")
            print(f"  prob_mal:   {r['prob_malicious']:.3f}")
            print(f"  reasons:    {', '.join(r['reasons'])}")
            if notes:
                print(f"  notes:      {notes}")
            print()

if __name__ == "__main__":
    main()
