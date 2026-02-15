"""Service layer for reconciliation operations."""

import uuid
import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import Payment, PaymentRepository
from .models import (
    ReconciliationReport,
    ReconciliationRequest,
    ReconciliationStatus,
    LocalTransaction,
    PSPTransaction,
)
from .psp_fetcher import get_psp_fetcher, PSPFetcherBase
from .reconciler import Reconciler
from .report import ReportGenerator

logger = logging.getLogger(__name__)


class ReconciliationService:
    """Service for executing and managing reconciliation jobs."""
    
    def __init__(
        self,
        session: AsyncSession,
        psp_fetcher: Optional[PSPFetcherBase] = None,
    ):
        """Initialize the reconciliation service.
        
        Args:
            session: Async database session.
            psp_fetcher: Optional PSP fetcher instance. Will create default if not provided.
        """
        self.session = session
        self.payment_repo = PaymentRepository(session)
        self._psp_fetcher = psp_fetcher
    
    def _get_psp_fetcher(self, provider: str = "stripe") -> PSPFetcherBase:
        """Get or create the PSP fetcher.
        
        Args:
            provider: PSP provider name.
        
        Returns:
            PSP fetcher instance.
        """
        if self._psp_fetcher:
            return self._psp_fetcher
        return get_psp_fetcher(provider)
    
    async def fetch_local_transactions(
        self,
        start_time: datetime,
        end_time: datetime,
        provider: str = "stripe",
    ) -> List[LocalTransaction]:
        """Fetch transactions from the local database for reconciliation.
        
        Args:
            start_time: Start of the time range.
            end_time: End of the time range.
            provider: PSP provider to filter by.
        
        Returns:
            List of LocalTransaction objects.
        """
        result = await self.session.execute(
            select(Payment)
            .where(
                and_(
                    Payment.created_at >= start_time,
                    Payment.created_at <= end_time,
                    Payment.provider == provider,
                )
            )
            .order_by(Payment.created_at)
        )
        
        payments = list(result.scalars().all())
        
        transactions = []
        for p in payments:
            transactions.append(LocalTransaction(
                id=p.id,
                provider_transaction_id=p.provider_transaction_id,
                amount=p.amount,
                currency=p.currency,
                status=p.status,
                captured_amount=p.captured_amount,
                refunded_amount=p.refunded_amount,
                created_at=p.created_at,
                updated_at=p.updated_at,
                metadata=p.metadata or {},
            ))
        
        logger.info(f"Fetched {len(transactions)} local transactions")
        return transactions
    
    async def run_reconciliation(
        self,
        request: ReconciliationRequest,
    ) -> ReconciliationReport:
        """Execute a reconciliation job.
        
        Args:
            request: Reconciliation request parameters.
        
        Returns:
            ReconciliationReport with results.
        """
        report_id = str(uuid.uuid4())
        
        report = ReconciliationReport(
            id=report_id,
            status=ReconciliationStatus.IN_PROGRESS,
            provider=request.provider,
            start_time=request.start_time,
            end_time=request.end_time,
            created_at=datetime.utcnow(),
        )
        
        logger.info(
            f"Starting reconciliation job {report_id} for {request.provider} "
            f"from {request.start_time} to {request.end_time}"
        )
        
        try:
            # Fetch local transactions
            local_transactions = await self.fetch_local_transactions(
                start_time=request.start_time,
                end_time=request.end_time,
                provider=request.provider,
            )
            report.total_local_records = len(local_transactions)
            
            # Fetch PSP transactions
            psp_fetcher = self._get_psp_fetcher(request.provider)
            psp_transactions = psp_fetcher.fetch_transactions(
                start_time=request.start_time,
                end_time=request.end_time,
            )
            report.total_psp_records = len(psp_transactions)
            
            # Run reconciliation
            reconciler = Reconciler(
                amount_tolerance=0,  # Exact matching
                ignore_metadata=True,  # Don't fail on metadata differences
            )
            
            matched, unmatched, discrepancies = reconciler.reconcile(
                local_transactions=local_transactions,
                psp_transactions=psp_transactions,
            )
            
            # Update report
            report.matched_records = matched
            report.unmatched_records = unmatched
            report.discrepancy_records = discrepancies
            report.total_matched = len(matched)
            report.total_unmatched = len(unmatched)
            report.total_discrepancies = len(discrepancies)
            report.status = ReconciliationStatus.COMPLETED
            report.completed_at = datetime.utcnow()
            
            logger.info(
                f"Reconciliation job {report_id} completed: "
                f"{report.total_matched} matched, "
                f"{report.total_unmatched} unmatched, "
                f"{report.total_discrepancies} discrepancies"
            )
            
        except Exception as e:
            logger.error(f"Reconciliation job {report_id} failed: {e}")
            report.status = ReconciliationStatus.FAILED
            report.error_message = str(e)
            report.completed_at = datetime.utcnow()
        
        return report
    
    def generate_report(
        self,
        report: ReconciliationReport,
        format: str = "json",
        include_details: bool = True,
    ) -> str:
        """Generate a formatted report from reconciliation results.
        
        Args:
            report: ReconciliationReport to format.
            format: Output format ('json', 'csv', 'text', 'detailed_text').
            include_details: Include detailed records (for JSON format).
        
        Returns:
            Formatted report string.
        """
        generator = ReportGenerator(report)
        
        if format == "json":
            return generator.to_json(include_details=include_details)
        elif format == "csv":
            return generator.to_csv(record_type="all")
        elif format == "text":
            return generator.to_summary_text()
        elif format == "detailed_text":
            return generator.to_detailed_text()
        else:
            raise ValueError(f"Unsupported report format: {format}")
