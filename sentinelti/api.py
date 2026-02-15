import os
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from .scoring import enrich_score  # adjust import if needed

from typing import List, Literal, Dict, Any
from pydantic import BaseModel

class HeuristicResult(BaseModel):
    score: float
    reasons: List[str]

class ScoreResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    url: str
    label: int
    prob_malicious: float
    heuristic: HeuristicResult
    final_label: Literal["benign", "suspicious", "malicious"]
    risk: Literal["low", "medium", "high"]
    reasons: List[str]
    meta: Dict[str, Any] | None = None


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


@app.post("/score-url", response_model=ScoreResponse, dependencies=[Depends(require_api_key)])
async def score_url(body: ScoreUrlRequest):
    result = enrich_score(body.url)
    result["meta"] = {"model": "xgb", "source": "kaggle+urlhaus"}
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)
