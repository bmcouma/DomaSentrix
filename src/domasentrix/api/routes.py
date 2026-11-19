"""DomaSentrix API routes."""

from fastapi import APIRouter, HTTPException

from domasentrix.api.schemas import TargetRequest, TargetValidationResponse
from domasentrix.core.target import TargetValidationError, normalize_domain

router = APIRouter(prefix="/v1", tags=["Domain Validation"])


@router.post("/targets/validate", response_model=TargetValidationResponse)
def validate_target(request: TargetRequest) -> TargetValidationResponse:
    try:
        normalized = normalize_domain(request.domain)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return TargetValidationResponse(
        valid=True,
        normalized_domain=normalized,
        message="Domain syntax is valid.",
    )
