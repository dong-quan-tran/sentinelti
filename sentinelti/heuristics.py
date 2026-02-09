"""
Heuristic URL analysis for SentinelTi.

This module inspects a URL for phishing and malware indicators
(e.g. raw IP hosts, suspicious tokens, uncommon TLDs) and returns
a numeric risk score plus human-readable reasons to enrich the
ML classifier output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any
from urllib.parse import urlparse

import tldextract


SUSPICIOUS_TOKENS = {
    "login", "log-in", "signin", "sign-in",
    "verify", "verification", "update", "secure",
    "account", "bank", "paypal", "appleid", "office365",
    "microsoft", "netflix", "payment", "invoice",
}

UNUSUAL_TLDS = {
    "xyz", "top", "club", "click", "link",
    "online", "work", "pw", "guru", "kim",
}

RAW_IP_SCORE = 2.0
AT_AUTHORITY_SCORE = 1.5
SUSPICIOUS_TOKEN_SCORE = 0.75
UNUSUAL_TLD_SCORE = 1.0
LONG_DOMAIN_SCORE = 0.5
DEEP_PATH_SCORE = 0.5


@dataclass
class HeuristicResult:
    score: float
    reasons: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)


def analyze_url(url: str) -> HeuristicResult:
    """
    Analyze a URL and return heuristic score + reasons.
    This does NOT call the ML model.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    score = 0.0
    reasons: List[str] = []
    features: Dict[str, Any] = {}

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Raw IP host (very rough check)
    if host.replace(".", "").isdigit():
        score += RAW_IP_SCORE
        reasons.append("URL uses a raw IP address as host (common in malicious infrastructure).")

    # '@' in authority part
    if "@" in parsed.netloc:
        score += AT_AUTHORITY_SCORE
        reasons.append("URL contains '@' in the authority part (possible obfuscation).")

    # Suspicious tokens in path/query
    lower_path_query = (path + "?" + query).lower()
    matched_tokens = sorted({t for t in SUSPICIOUS_TOKENS if t in lower_path_query})
    if matched_tokens:
        token_score = SUSPICIOUS_TOKEN_SCORE * len(matched_tokens)
        score += token_score
        reasons.append(
            f"Contains suspicious tokens often seen in phishing URLs: {', '.join(matched_tokens)}."
        )

    # Unusual TLD
    tld = (ext.suffix or "").lower()
    features["tld"] = tld
    if tld in UNUSUAL_TLDS:
        score += UNUSUAL_TLD_SCORE
        reasons.append(f"Uses an uncommon TLD: .{tld}.")

    # Long domain (subdomain + domain)
    domain_length = len(ext.domain or "") + len(ext.subdomain or "")
    features["domain_length"] = domain_length
    if domain_length >= 20:
        score += LONG_DOMAIN_SCORE
        reasons.append("Domain part is unusually long, which can indicate obfuscation.")

    # Deep path
    depth = len([p for p in path.split("/") if p])
    features["path_depth"] = depth
    if depth >= 4:
        score += DEEP_PATH_SCORE
        reasons.append("URL path is deeply nested, often used to hide payloads or phishing pages.")

    features["raw_score"] = score

    return HeuristicResult(score=score, reasons=reasons, features=features)
