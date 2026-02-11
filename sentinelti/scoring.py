"""
Scoring and enrichment logic for SentinelTi.

This module combines the ML URL classifier output with heuristic
signals to produce a final label, risk level, and explanations
suitable for CLI and API consumers.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

from .heuristics import analyze_url
from .ml.service import score_url as ml_score_url  # adjust path if needed


def enrich_score(url: str) -> Dict[str, Any]:
    """
    Run the ML model and heuristics on a URL and return an enriched result.

    Returns a dict with at least:
      - url
      - label (ML label)
      - prob_malicious (float)
      - heuristic (nested dict)
      - final_label: 'benign' | 'suspicious' | 'malicious'
      - risk: 'low' | 'medium' | 'high'
      - reasons: list[str]
    """
    ml_result = ml_score_url(url)  # existing function: {url, label, prob_malicious}
    heur = analyze_url(url)

    p = float(ml_result["prob_malicious"])
    h = float(heur.score)

    # Strong ML + strong heuristics => malicious / high
    if (p >= 0.95 and h >= 2.0) or h >= 3.5:
        final_label = "malicious"
        risk = "high"

    # Clear benign: very low ML, no heuristic signals
    elif p <= 0.05 and h == 0.0:
        final_label = "benign"
        risk = "low"

    # Mostly benign but some mild heuristic noise
    elif p <= 0.10 and h < 1.5:
        final_label = "benign"
        risk = "low"

    # Medium risk: either ML is moderately high or heuristics indicate clear phishing structure
    elif p >= 0.80 or h >= 1.5:
        final_label = "suspicious"
        risk = "medium"

    # Default: suspicious if we have any heuristic score, otherwise low-risk benign
    else:
        if h > 0.0:
            final_label = "suspicious"
            risk = "medium"
        else:
            final_label = "benign"
            risk = "low"


    reasons = list(heur.reasons)
    if final_label == "benign" and not reasons:
        reasons.append("No strong malicious indicators detected by model or heuristics.")
    elif not reasons:
        reasons.append("Flagged primarily by the ML classifier score.")

    return {
        **ml_result,
        "heuristic": asdict(heur),
        "final_label": final_label,
        "risk": risk,
        "reasons": reasons,
    }
