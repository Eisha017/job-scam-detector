"""
Job Scam Detector — Step 7: Structured Output Schema
Defines the shape of the final scam risk report. Using Pydantic means we can
force Claude to return clean, validated JSON instead of parsing free text.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional


class RedFlag(BaseModel):
    signal: str = Field(description="Short name of the red flag, e.g. 'upfront_fee'")
    matched_text: Optional[str] = Field(
        default=None, description="The specific phrase that triggered this flag, if any"
    )
    explanation: str = Field(
        description="One sentence explaining why this signal is suspicious"
    )


class ScamReport(BaseModel):
    risk_score: int = Field(
        ge=0, le=100,
        description="0 = definitely legitimate, 100 = definitely a scam"
    )
    verdict: Literal["likely legitimate", "uncertain", "likely scam"]
    red_flags: list[RedFlag] = Field(
        default_factory=list,
        description="All red flags identified, from both rule-based detectors and Claude's own reading"
    )
    reassuring_signals: list[str] = Field(
        default_factory=list,
        description="Signals suggesting the posting IS legitimate, e.g. clear salary range, real company domain"
    )
    summary: str = Field(
        description="2-3 sentence plain-language explanation of the verdict for the job seeker"
    )
    safety_reminder: str = Field(
        default="",
        description="Fixed advisory added programmatically after generation, not filled by the model"
    )
