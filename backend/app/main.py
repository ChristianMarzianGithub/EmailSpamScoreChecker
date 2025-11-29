from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .analyzer import AnalysisResult, analyze_email


class AnalyzeRequest(BaseModel):
    raw: str


app = FastAPI(title="Email Spam Score Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest):
    try:
        result = analyze_email(request.raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - unexpected errors
        raise HTTPException(status_code=500, detail="Analysis failed") from exc
    return result


@app.get("/health")
async def health():
    return {"status": "ok"}
