from sentinelti.ml.service import score_url, score_urls


def test_score_url_basic():
    result = score_url("http://www.example.com/")
    assert "url" in result
    assert "label" in result
    assert "prob_malicious" in result
    assert isinstance(result["label"], int)
    assert isinstance(result["prob_malicious"], float)


def test_score_urls_list():
    urls = ["http://www.example.com/", "http://test.com/"]
    results = score_urls(urls)
    assert len(results) == len(urls)
