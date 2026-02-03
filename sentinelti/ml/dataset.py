from __future__ import annotations

from typing import List, Tuple

import numpy as np

from sentinelti.ml.features import extract_features


# Temporary benign examples; we'll replace with real data later.
BENIGN_URLS = [
    "http://www.google.com/",
    "http://www.microsoft.com/",
    "http://www.apple.com/",
    "http://www.bbc.com/news",
    "http://www.reddit.com/",
    "http://www.github.com/",
]

# Temporary malicious-looking examples if we don't yet query URLhaus here.
MALICIOUS_URLS = [
    "http://192.168.1.10/login.php?user=admin",
    "http://secure-update-account.com/login/confirm",
    "http://paypal.verify-account-secure.com/update",
    "http://banking-secure-login.xyz/account/verify",
]


def build_dummy_dataset() -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Build a small dummy dataset of feature vectors and labels.

    Returns:
        X: numpy array of shape (n_samples, n_features)
        y: numpy array of shape (n_samples,)
        feature_names: list of feature names in column order
    """
    urls: List[Tuple[str, int]] = []
    for u in BENIGN_URLS:
        urls.append((u, 0))
    for u in MALICIOUS_URLS:
        urls.append((u, 1))

    feature_dicts = [extract_features(u) for u, _ in urls]

    # Use all numeric feature keys (ignore helper keys like "_tld_raw").
    numeric_keys = [k for k in feature_dicts[0].keys() if not k.startswith("_")]

    X = np.array([[fd[k] for k in numeric_keys] for fd in feature_dicts], dtype=float)
    y = np.array([label for _, label in urls], dtype=int)

    return X, y, numeric_keys
