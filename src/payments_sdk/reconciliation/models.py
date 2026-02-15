"""Models for payment reconciliation."""

import enum
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class DiscrepancyType(str, enum.Enum):
    """Types of discrepancies that can be found during reconciliation."""
    AMOUNT_MISMATCH = "amount_mismatch"
    STATUS_MISMATCH = "status_mismatch"
    CURRENCY_MISMATCH = "currency_mismatch"
    MISSING_IN_LOCAL = "missing_in_local"
    MISSING_IN_PSP = "missing_in_psp"
    METADATA_MISMATCH = "metadata_mismatch"


class ReconciliationStatus(str, enum.Enum):
    """Status of a reconciliation job."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class PSPTransaction(BaseModel):
    """Represents a transaction fetched from the PSP (e.g., Stripe)."""
    id: str = Field(..., description="Transaction ID from the PSP")
    amount: int = Field(..., description="Transaction amount in minor units")
    currency: str = Field(..., description="Three-letter currency code")
    status: str = Field(..., description="Transaction status from PSP")
    created_at: datetime = Field(..., description="Transaction creation time")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw PSP response data")
    
    class Config:
        from_attributes = True


class LocalTransaction(BaseModel):
    """Represents a transaction from the local database."""
    id: str = Field(..., description="Internal payment ID")
    provider_transaction_id: Optional[str] = Field(None, description="PSP transaction ID")
    amount: int = Field(..., description="Transaction amount in minor units")
    currency: str = Field(..., description="Three-letter currency code")
    status: str = Field(..., description="Transaction status")
    captured_amount: int = Field(default=0, description="Captured amount in minor units")
    refunded_amount: int = Field(default=0, description="Refunded amount in minor units")
    created_at: datetime = Field(..., description="Transaction creation time")
    updated_at: datetime = Field(..., description="Transaction last update time")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    class Config:
        from_attributes = True


class MatchedRecord(BaseModel):
    """Represents a successfully matched record between local and PSP."""
    local_id: str = Field(..., description="Internal payment ID")
    psp_id: str = Field(..., description="PSP transaction ID")
    amount: int = Field(..., description="Transaction amount")
    currency: str = Field(..., description="Currency code")
    status: str = Field(..., description="Status (matched)")
    matched_at: datetime = Field(default_factory=datetime.utcnow)


class UnmatchedRecord(BaseModel):
    """Represents a record that exists only in one source."""
    source: str = Field(..., description="Source of the record ('local' or 'psp')")
    transaction_id: str = Field(..., description="Transaction ID")
    amount: int = Field(..., description="Transaction amount")
    currency: str = Field(..., description="Currency code")
    status: str = Field(..., description="Transaction status")
    created_at: datetime = Field(..., description="Transaction creation time")
    reason: DiscrepancyType = Field(..., description="Reason for being unmatched")


class DiscrepancyRecord(BaseModel):
    """Represents a record with discrepancies between local and PSP."""
    local_id: str = Field(..., description="Internal payment ID")
    psp_id: str = Field(..., description="PSP transaction ID")
    discrepancy_type: DiscrepancyType = Field(..., description="Type of discrepancy")
    local_value: Any = Field(..., description="Value from local database")
    psp_value: Any = Field(..., description="Value from PSP")
    field_name: str = Field(..., description="Name of the field with discrepancy")
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class ReconciliationReport(BaseModel):
    """Complete reconciliation report with all findings."""
    id: str = Field(..., description="Report ID")
    status: ReconciliationStatus = Field(default=ReconciliationStatus.PENDING)
    provider: str = Field(default="stripe", description="PSP provider name")
    start_time: datetime = Field(..., description="Start of reconciliation time range")
    end_time: datetime = Field(..., description="End of reconciliation time range")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None, description="Time when reconciliation completed")
    
    # Statistics
    total_local_records: int = Field(default=0)
    total_psp_records: int = Field(default=0)
    total_matched: int = Field(default=0)
    total_unmatched: int = Field(default=0)
    total_discrepancies: int = Field(default=0)
    
    # Detailed records
    matched_records: List[MatchedRecord] = Field(default_factory=list)
    unmatched_records: List[UnmatchedRecord] = Field(default_factory=list)
    discrepancy_records: List[DiscrepancyRecord] = Field(default_factory=list)
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if reconciliation failed")
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Return a summary of the report without detailed records."""
        return {
            "id": self.id,
            "status": self.status.value,
            "provider": self.provider,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "statistics": {
                "total_local_records": self.total_local_records,
                "total_psp_records": self.total_psp_records,
                "total_matched": self.total_matched,
                "total_unmatched": self.total_unmatched,
                "total_discrepancies": self.total_discrepancies,
                "match_rate": (
                    f"{(self.total_matched / self.total_local_records * 100):.2f}%"
                    if self.total_local_records > 0 else "N/A"
                ),
            },
            "error_message": self.error_message,
        }
    
    def to_full_dict(self) -> Dict[str, Any]:
        """Return the complete report including all records."""
        result = self.to_summary_dict()
        result["matched_records"] = [r.model_dump() for r in self.matched_records]
        result["unmatched_records"] = [r.model_dump() for r in self.unmatched_records]
        result["discrepancy_records"] = [r.model_dump() for r in self.discrepancy_records]
        return result


class ReconciliationRequest(BaseModel):
    """Request model for starting a reconciliation job."""
    start_time: datetime = Field(..., description="Start of time range to reconcile")
    end_time: datetime = Field(..., description="End of time range to reconcile")
    provider: str = Field(default="stripe", description="PSP provider name")
    include_details: bool = Field(default=True, description="Include detailed records in report")
