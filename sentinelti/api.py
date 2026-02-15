import os
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from .scoring import enrich_score  # adjust import if needed


API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("SENTINELTI_API_KEY", "change-me")

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def require_api_key(api_key: str | None = Depends(api_key_header)):
    if api_key is None or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


app = FastAPI(title="SentinelTI", version="0.1.0")


class ScoreUrlRequest(BaseModel):
    url: str


class ScoreUrlsRequest(BaseModel):
    urls: List[str]


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/score-url", dependencies=[Depends(require_api_key)])
async def score_url(body: ScoreUrlRequest):
    result = enrich_score(body.url)
    return result


@app.post("/score-urls", dependencies=[Depends(require_api_key)])
async def score_urls(body: ScoreUrlsRequest):
    results = [enrich_score(url) for url in body.urls]
    return {"results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)
