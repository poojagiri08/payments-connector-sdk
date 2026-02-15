"""Reconciliation logic for comparing local and PSP records."""

import logging
from datetime import datetime
from typing import List, Dict, Tuple, Set

from .models import (
    PSPTransaction,
    LocalTransaction,
    MatchedRecord,
    UnmatchedRecord,
    DiscrepancyRecord,
    DiscrepancyType,
)

logger = logging.getLogger(__name__)


class Reconciler:
    """Reconciliation engine for comparing local and PSP transactions."""
    
    # Status mappings for comparison (PSP status -> canonical statuses)
    STATUS_EQUIVALENTS: Dict[str, Set[str]] = {
        "authorized": {"authorized", "requires_capture"},
        "captured": {"captured", "succeeded"},
        "pending": {"pending", "processing", "requires_payment_method", "requires_confirmation"},
        "pending_mfa": {"pending_mfa", "requires_action"},
        "voided": {"voided", "canceled"},
        "refunded": {"refunded"},
        "partially_refunded": {"partially_refunded"},
        "failed": {"failed"},
    }
    
    def __init__(
        self,
        amount_tolerance: int = 0,
        ignore_metadata: bool = False,
    ):
        """Initialize the reconciler.
        
        Args:
            amount_tolerance: Tolerance for amount differences (in minor units).
                             Set to 0 for exact matching.
            ignore_metadata: If True, skip metadata comparison.
        """
        self.amount_tolerance = amount_tolerance
        self.ignore_metadata = ignore_metadata
    
    def _normalize_status(self, status: str) -> str:
        """Normalize status to a canonical form for comparison.
        
        Args:
            status: Status string from either source.
        
        Returns:
            Normalized canonical status.
        """
        status_lower = status.lower()
        for canonical, equivalents in self.STATUS_EQUIVALENTS.items():
            if status_lower in equivalents or status_lower == canonical:
                return canonical
        return status_lower
    
    def _statuses_match(self, local_status: str, psp_status: str) -> bool:
        """Check if two statuses are equivalent.
        
        Args:
            local_status: Status from local database.
            psp_status: Status from PSP.
        
        Returns:
            True if statuses are equivalent.
        """
        return self._normalize_status(local_status) == self._normalize_status(psp_status)
    
    def _amounts_match(self, local_amount: int, psp_amount: int) -> bool:
        """Check if two amounts are within tolerance.
        
        Args:
            local_amount: Amount from local database.
            psp_amount: Amount from PSP.
        
        Returns:
            True if amounts are within tolerance.
        """
        return abs(local_amount - psp_amount) <= self.amount_tolerance
    
    def _compare_transactions(
        self,
        local: LocalTransaction,
        psp: PSPTransaction,
    ) -> List[DiscrepancyRecord]:
        """Compare a matched pair of transactions for discrepancies.
        
        Args:
            local: Local database transaction.
            psp: PSP transaction.
        
        Returns:
            List of DiscrepancyRecord for any found discrepancies.
        """
        discrepancies: List[DiscrepancyRecord] = []
        now = datetime.utcnow()
        
        # Compare amounts
        if not self._amounts_match(local.amount, psp.amount):
            discrepancies.append(DiscrepancyRecord(
                local_id=local.id,
                psp_id=psp.id,
                discrepancy_type=DiscrepancyType.AMOUNT_MISMATCH,
                local_value=local.amount,
                psp_value=psp.amount,
                field_name="amount",
                detected_at=now,
            ))
        
        # Compare statuses
        if not self._statuses_match(local.status, psp.status):
            discrepancies.append(DiscrepancyRecord(
                local_id=local.id,
                psp_id=psp.id,
                discrepancy_type=DiscrepancyType.STATUS_MISMATCH,
                local_value=local.status,
                psp_value=psp.status,
                field_name="status",
                detected_at=now,
            ))
        
        # Compare currencies
        if local.currency.upper() != psp.currency.upper():
            discrepancies.append(DiscrepancyRecord(
                local_id=local.id,
                psp_id=psp.id,
                discrepancy_type=DiscrepancyType.CURRENCY_MISMATCH,
                local_value=local.currency,
                psp_value=psp.currency,
                field_name="currency",
                detected_at=now,
            ))
        
        # Compare metadata (optional)
        if not self.ignore_metadata and local.metadata and psp.metadata:
            if local.metadata != psp.metadata:
                discrepancies.append(DiscrepancyRecord(
                    local_id=local.id,
                    psp_id=psp.id,
                    discrepancy_type=DiscrepancyType.METADATA_MISMATCH,
                    local_value=local.metadata,
                    psp_value=psp.metadata,
                    field_name="metadata",
                    detected_at=now,
                ))
        
        return discrepancies
    
    def reconcile(
        self,
        local_transactions: List[LocalTransaction],
        psp_transactions: List[PSPTransaction],
    ) -> Tuple[List[MatchedRecord], List[UnmatchedRecord], List[DiscrepancyRecord]]:
        """Reconcile local transactions against PSP transactions.
        
        The reconciliation process:
        1. Build lookup maps for efficient matching
        2. Match transactions by provider_transaction_id
        3. Compare matched pairs for discrepancies
        4. Identify unmatched records from both sources
        
        Args:
            local_transactions: List of transactions from local database.
            psp_transactions: List of transactions from PSP.
        
        Returns:
            Tuple of (matched_records, unmatched_records, discrepancy_records).
        """
        matched: List[MatchedRecord] = []
        unmatched: List[UnmatchedRecord] = []
        discrepancies: List[DiscrepancyRecord] = []
        
        now = datetime.utcnow()
        
        # Build lookup maps
        # PSP transactions keyed by their ID
        psp_by_id: Dict[str, PSPTransaction] = {t.id: t for t in psp_transactions}
        
        # Track which PSP transactions have been matched
        matched_psp_ids: Set[str] = set()
        
        logger.info(
            f"Starting reconciliation: {len(local_transactions)} local, "
            f"{len(psp_transactions)} PSP transactions"
        )
        
        # Process local transactions
        for local in local_transactions:
            psp_id = local.provider_transaction_id
            
            if not psp_id:
                # Local transaction without PSP ID
                unmatched.append(UnmatchedRecord(
                    source="local",
                    transaction_id=local.id,
                    amount=local.amount,
                    currency=local.currency,
                    status=local.status,
                    created_at=local.created_at,
                    reason=DiscrepancyType.MISSING_IN_PSP,
                ))
                continue
            
            psp = psp_by_id.get(psp_id)
            
            if psp:
                # Found matching PSP transaction
                matched_psp_ids.add(psp_id)
                
                # Check for discrepancies
                txn_discrepancies = self._compare_transactions(local, psp)
                
                if txn_discrepancies:
                    discrepancies.extend(txn_discrepancies)
                else:
                    # Perfect match
                    matched.append(MatchedRecord(
                        local_id=local.id,
                        psp_id=psp_id,
                        amount=local.amount,
                        currency=local.currency,
                        status=local.status,
                        matched_at=now,
                    ))
            else:
                # Local transaction references PSP ID that doesn't exist in PSP data
                unmatched.append(UnmatchedRecord(
                    source="local",
                    transaction_id=local.id,
                    amount=local.amount,
                    currency=local.currency,
                    status=local.status,
                    created_at=local.created_at,
                    reason=DiscrepancyType.MISSING_IN_PSP,
                ))
        
        # Find PSP transactions not matched to any local transaction
        for psp_id, psp in psp_by_id.items():
            if psp_id not in matched_psp_ids:
                unmatched.append(UnmatchedRecord(
                    source="psp",
                    transaction_id=psp_id,
                    amount=psp.amount,
                    currency=psp.currency,
                    status=psp.status,
                    created_at=psp.created_at,
                    reason=DiscrepancyType.MISSING_IN_LOCAL,
                ))
        
        logger.info(
            f"Reconciliation complete: {len(matched)} matched, "
            f"{len(unmatched)} unmatched, {len(discrepancies)} discrepancies"
        )
        
        return matched, unmatched, discrepancies
