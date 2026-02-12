from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from .scoring import enrich_score  # adjust import if needed

app = FastAPI(title="SentinelTi API", version="0.1.0")


class ScoreUrlRequest(BaseModel):
    url: str


class ScoreUrlsRequest(BaseModel):
    urls: List[str]


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/score-url")
async def score_url(body: ScoreUrlRequest):
    result = enrich_score(body.url)
    return result


@app.post("/score-urls")
async def score_urls(body: ScoreUrlsRequest):
    results = [enrich_score(url) for url in body.urls]
    return {"results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)
