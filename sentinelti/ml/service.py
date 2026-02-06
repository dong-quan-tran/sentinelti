from __future__ import annotations

from typing import Dict, List

from sentinelti.ml.predict import predict_url


def score_url(url: str) -> Dict[str, object]:
    """
    Score a single URL using the trained classifier.

    Returns:
        {
            "url": str,
            "label": int,              # 0 = benign, 1 = malicious
            "prob_malicious": float,   # model score for class 1
        }
    """
    label, prob_malicious = predict_url(url)
    return {
        "url": url,
        "label": label,
        "prob_malicious": prob_malicious,
    }


def score_urls(urls: List[str]) -> List[Dict[str, object]]:
    """
    Score a list of URLs.

    Returns a list of dicts as in score_url.
    """
    return [score_url(u) for u in urls]
