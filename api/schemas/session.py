"""
Pydantic schemas for session endpoints.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SessionCreate(BaseModel):
    """Request body for creating a new training session.

    `username` is deprecated and ignored: the session is always created
    for the authenticated user (resolved from the Firebase token, or the
    demo user in local dev). The field is kept as an optional, no-op
    value so existing clients that still send it do not fail validation.
    """
    username: Optional[str] = Field(
        None,
        max_length=64,
        examples=["analyst_01"],
        description="Deprecated and ignored — the acting user is derived "
                    "from the auth token, not this field.",
    )
    scenario_id: str = Field(..., examples=["ransomware"])
    role: str = Field(..., examples=["blue_team"], pattern="^(red_team|blue_team|full_spectrum)$")
    difficulty: str = Field("medium", pattern="^(beginner|medium|hard|expert)$")


class SessionResponse(BaseModel):
    """Response body for a session."""
    id: str
    user_id: str
    scenario_id: str
    role: str
    difficulty: str
    status: str
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_at: datetime
    model_config = {"from_attributes": True}


class SessionStatusUpdate(BaseModel):
    """Request body for updating session status."""
    status: str = Field(..., pattern="^(running|paused|completed|aborted)$")
