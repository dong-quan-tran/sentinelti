from pathlib import Path
import subprocess
import sys


def test_score_file_runs(tmp_path: Path):
    # create a temporary urls.txt
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("http://example.com\nhttp://192.168.0.1/login\n", encoding="utf-8")

    # run the CLI as a module
    result = subprocess.run(
        [sys.executable, "-m", "sentinelti.cli", "score-file", str(urls_file), "--output-format", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "[" in result.stdout
    assert "http://example.com" in result.stdout
    assert "http://192.168.0.1/login" in result.stdout