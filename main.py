"""
Job Scam Detector — Step 10: FastAPI Wrapper
Exposes the detection pipeline as a real HTTP API. This is what your
Streamlit demo and Chrome extension will both call into.

Run locally with: uvicorn main:app --reload
Then visit http://127.0.0.1:8000/docs for interactive API docs (auto-generated).
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from analyzer import analyze_posting
from schema import ScamReport

app = FastAPI(
    title="Job Scam Detector API",
    description="Analyzes job postings and recruiter messages for scam indicators.",
    version="1.0.0",
)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=20, description="The job posting or message text to analyze")
    claimed_company_domain: Optional[str] = Field(
        None, description="The real company's domain, e.g. 'microsoft.com' (optional)"
    )
    sender_email_domain: Optional[str] = Field(
        None, description="The domain the recruiter actually contacted you from (optional)"
    )


@app.get("/")
def root():
    return {"status": "ok", "message": "Job Scam Detector API is running. See /docs for usage."}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze", response_model=ScamReport)
def analyze(request: AnalyzeRequest):
    if len(request.text.strip()) < 20:
        raise HTTPException(status_code=400, detail="Text too short to analyze meaningfully.")

    try:
        report = analyze_posting(
            text=request.text,
            claimed_company_domain=request.claimed_company_domain,
            sender_email_domain=request.sender_email_domain,
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Analysis failed: {str(e)}")
