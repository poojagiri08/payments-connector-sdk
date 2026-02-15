"""API endpoints for reconciliation operations."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..auth import verify_api_key, limiter
from .models import ReconciliationRequest, ReconciliationStatus
from .service import ReconciliationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reconciliation", tags=["reconciliation"])


class ReconciliationRequestBody(BaseModel):
    """Request body for starting a reconciliation job."""
    start_time: datetime = Field(..., description="Start of time range to reconcile")
    end_time: datetime = Field(..., description="End of time range to reconcile")
    provider: str = Field(default="stripe", description="PSP provider name")


class ReconciliationSummaryResponse(BaseModel):
    """Summary response for reconciliation job."""
    id: str
    status: str
    provider: str
    start_time: datetime
    end_time: datetime
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_local_records: int = 0
    total_psp_records: int = 0
    total_matched: int = 0
    total_unmatched: int = 0
    total_discrepancies: int = 0
    match_rate: str = "N/A"
    error_message: Optional[str] = None


@router.post("/jobs", response_model=ReconciliationSummaryResponse)
async def create_reconciliation_job(
    body: ReconciliationRequestBody,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    """
    Start a new reconciliation job.
    
    Compares local payment records with PSP records for the specified time range.
    Returns a summary of the reconciliation results including match statistics.
    """
    if body.start_time >= body.end_time:
        raise HTTPException(
            status_code=400,
            detail="start_time must be before end_time"
        )
    
    service = ReconciliationService(db)
    
    request = ReconciliationRequest(
        start_time=body.start_time,
        end_time=body.end_time,
        provider=body.provider,
    )
    
    logger.info(
        f"Starting reconciliation job for {body.provider} "
        f"from {body.start_time} to {body.end_time}"
    )
    
    report = await service.run_reconciliation(request)
    summary = report.to_summary_dict()
    
    return ReconciliationSummaryResponse(
        id=summary["id"],
        status=summary["status"],
        provider=summary["provider"],
        start_time=report.start_time,
        end_time=report.end_time,
        created_at=report.created_at,
        completed_at=report.completed_at,
        total_local_records=summary["statistics"]["total_local_records"],
        total_psp_records=summary["statistics"]["total_psp_records"],
        total_matched=summary["statistics"]["total_matched"],
        total_unmatched=summary["statistics"]["total_unmatched"],
        total_discrepancies=summary["statistics"]["total_discrepancies"],
        match_rate=summary["statistics"]["match_rate"],
        error_message=summary.get("error_message"),
    )


@router.post("/jobs/report")
async def create_reconciliation_report(
    body: ReconciliationRequestBody,
    include_details: bool = Query(default=True, description="Include detailed records"),
    format: str = Query(default="json", description="Output format: json, csv, text"),
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    """
    Run reconciliation and generate a detailed report.
    
    Returns the full reconciliation report including:
    - Matched records (transactions that match between local and PSP)
    - Unmatched records (transactions missing in one source)
    - Discrepancy records (transactions with field mismatches)
    """
    if body.start_time >= body.end_time:
        raise HTTPException(
            status_code=400,
            detail="start_time must be before end_time"
        )
    
    if format not in ("json", "csv", "text", "detailed_text"):
        raise HTTPException(
            status_code=400,
            detail="format must be one of: json, csv, text, detailed_text"
        )
    
    service = ReconciliationService(db)
    
    request = ReconciliationRequest(
        start_time=body.start_time,
        end_time=body.end_time,
        provider=body.provider,
        include_details=include_details,
    )
    
    report = await service.run_reconciliation(request)
    
    if format == "json":
        return report.to_full_dict() if include_details else report.to_summary_dict()
    else:
        # Return as plain text for non-JSON formats
        from fastapi.responses import PlainTextResponse
        output = service.generate_report(
            report=report,
            format=format,
            include_details=include_details,
        )
        content_type = "text/csv" if format == "csv" else "text/plain"
        return PlainTextResponse(content=output, media_type=content_type)


@router.get("/health")
async def reconciliation_health():
    """Health check endpoint for reconciliation service."""
    return {"status": "healthy", "service": "reconciliation"}
