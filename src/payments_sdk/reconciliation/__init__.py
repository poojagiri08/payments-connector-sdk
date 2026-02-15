"""Reconciliation module for payment systems.

This module provides tools for reconciling payment records between
the local database and payment service providers (PSPs) like Stripe.

Features:
- Fetch transactions from PSP for a given time range
- Compare local database records with PSP records
- Generate detailed reconciliation reports
- Support for matched, unmatched, and discrepancy tracking
"""

from .models import (
    DiscrepancyType,
    ReconciliationStatus,
    PSPTransaction,
    LocalTransaction,
    MatchedRecord,
    UnmatchedRecord,
    DiscrepancyRecord,
    ReconciliationReport,
    ReconciliationRequest,
)
from .psp_fetcher import (
    PSPFetcherBase,
    StripeFetcher,
    get_psp_fetcher,
)
from .reconciler import Reconciler
from .service import ReconciliationService
from .report import ReportGenerator

__all__ = [
    # Models
    "DiscrepancyType",
    "ReconciliationStatus",
    "PSPTransaction",
    "LocalTransaction",
    "MatchedRecord",
    "UnmatchedRecord",
    "DiscrepancyRecord",
    "ReconciliationReport",
    "ReconciliationRequest",
    # PSP Fetchers
    "PSPFetcherBase",
    "StripeFetcher",
    "get_psp_fetcher",
    # Core Components
    "Reconciler",
    "ReconciliationService",
    "ReportGenerator",
]
