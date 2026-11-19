"""Request and response schemas."""

from pydantic import BaseModel, Field


class TargetRequest(BaseModel):
    domain: str = Field(
        min_length=1,
        max_length=253,
        description="Domain to validate.",
        examples=["example.com"],
    )


class TargetValidationResponse(BaseModel):
    valid: bool
    normalized_domain: str
    message: str
