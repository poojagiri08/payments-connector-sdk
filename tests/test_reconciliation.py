"""Tests for the reconciliation module."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, AsyncMock

from payments_sdk.database import (
    Base,
    Payment,
    PaymentStatus,
    create_async_engine,
    get_async_session_factory,
)
from payments_sdk.reconciliation import (
    ReconciliationService,
    ReconciliationRequest,
    ReconciliationStatus,
    Reconciler,
    ReportGenerator,
    DiscrepancyType,
    PSPTransaction,
    LocalTransaction,
    MatchedRecord,
    UnmatchedRecord,
    DiscrepancyRecord,
    ReconciliationReport,
)


@pytest.fixture
async def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine(
        database_url="sqlite+aiosqlite:///:memory:",
        echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    """Create a database session for testing."""
    session_factory = get_async_session_factory(db_engine)
    async with session_factory() as session:
        yield session


@pytest.fixture
def sample_psp_transactions():
    """Create sample PSP transactions for testing."""
    now = datetime.utcnow()
    return [
        PSPTransaction(
            id="pi_001",
            amount=1000,
            currency="USD",
            status="captured",
            created_at=now - timedelta(hours=1),
            metadata={"order_id": "order_001"},
        ),
        PSPTransaction(
            id="pi_002",
            amount=2500,
            currency="USD",
            status="authorized",
            created_at=now - timedelta(hours=2),
            metadata={"order_id": "order_002"},
        ),
        PSPTransaction(
            id="pi_003",
            amount=500,
            currency="EUR",
            status="captured",
            created_at=now - timedelta(hours=3),
            metadata={},
        ),
    ]


@pytest.fixture
def sample_local_transactions():
    """Create sample local transactions for testing."""
    now = datetime.utcnow()
    return [
        LocalTransaction(
            id="local_001",
            provider_transaction_id="pi_001",
            amount=1000,
            currency="USD",
            status="captured",
            captured_amount=1000,
            refunded_amount=0,
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
            metadata={"order_id": "order_001"},
        ),
        LocalTransaction(
            id="local_002",
            provider_transaction_id="pi_002",
            amount=2500,
            currency="USD",
            status="authorized",
            captured_amount=0,
            refunded_amount=0,
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=2),
            metadata={"order_id": "order_002"},
        ),
        # This one has a different amount (discrepancy)
        LocalTransaction(
            id="local_003",
            provider_transaction_id="pi_003",
            amount=600,  # Different from PSP (500)
            currency="EUR",
            status="captured",
            captured_amount=600,
            refunded_amount=0,
            created_at=now - timedelta(hours=3),
            updated_at=now - timedelta(hours=3),
            metadata={},
        ),
    ]


class TestReconciler:
    """Tests for the Reconciler class."""
    
    def test_reconcile_perfect_match(self, sample_psp_transactions, sample_local_transactions):
        """Test reconciliation with matching transactions."""
        # Use only the first two transactions which match perfectly
        psp = sample_psp_transactions[:2]
        local = sample_local_transactions[:2]
        
        reconciler = Reconciler()
        matched, unmatched, discrepancies = reconciler.reconcile(local, psp)
        
        assert len(matched) == 2
        assert len(unmatched) == 0
        assert len(discrepancies) == 0
    
    def test_reconcile_amount_discrepancy(self, sample_psp_transactions, sample_local_transactions):
        """Test reconciliation detects amount discrepancy."""
        # Include the third transaction which has an amount mismatch
        psp = sample_psp_transactions
        local = sample_local_transactions
        
        reconciler = Reconciler()
        matched, unmatched, discrepancies = reconciler.reconcile(local, psp)
        
        # First two should match, third has discrepancy
        assert len(matched) == 2
        assert len(unmatched) == 0
        assert len(discrepancies) == 1
        
        disc = discrepancies[0]
        assert disc.discrepancy_type == DiscrepancyType.AMOUNT_MISMATCH
        assert disc.local_value == 600
        assert disc.psp_value == 500
    
    def test_reconcile_missing_in_psp(self, sample_psp_transactions):
        """Test reconciliation when transaction is missing in PSP."""
        now = datetime.utcnow()
        local = [
            LocalTransaction(
                id="local_999",
                provider_transaction_id="pi_nonexistent",
                amount=1000,
                currency="USD",
                status="captured",
                captured_amount=1000,
                refunded_amount=0,
                created_at=now,
                updated_at=now,
            ),
        ]
        
        reconciler = Reconciler()
        matched, unmatched, discrepancies = reconciler.reconcile(local, sample_psp_transactions)
        
        # Should have 3 unmatched (3 PSP not in local, 1 local not in PSP)
        assert len(matched) == 0
        # All 3 PSP are missing in local + 1 local is missing in PSP
        assert len(unmatched) == 4
        
        missing_in_psp = [u for u in unmatched if u.reason == DiscrepancyType.MISSING_IN_PSP]
        assert len(missing_in_psp) == 1
        assert missing_in_psp[0].transaction_id == "local_999"
    
    def test_reconcile_missing_in_local(self, sample_local_transactions):
        """Test reconciliation when transaction is missing in local."""
        now = datetime.utcnow()
        psp = [
            PSPTransaction(
                id="pi_extra",
                amount=5000,
                currency="USD",
                status="captured",
                created_at=now,
            ),
        ]
        
        reconciler = Reconciler()
        matched, unmatched, discrepancies = reconciler.reconcile(sample_local_transactions, psp)
        
        missing_in_local = [u for u in unmatched if u.reason == DiscrepancyType.MISSING_IN_LOCAL]
        assert len(missing_in_local) == 1
        assert missing_in_local[0].transaction_id == "pi_extra"
    
    def test_reconcile_status_mismatch(self):
        """Test reconciliation detects status mismatch."""
        now = datetime.utcnow()
        
        psp = [
            PSPTransaction(
                id="pi_001",
                amount=1000,
                currency="USD",
                status="captured",
                created_at=now,
            ),
        ]
        
        local = [
            LocalTransaction(
                id="local_001",
                provider_transaction_id="pi_001",
                amount=1000,
                currency="USD",
                status="pending",  # Different status
                captured_amount=0,
                refunded_amount=0,
                created_at=now,
                updated_at=now,
            ),
        ]
        
        reconciler = Reconciler()
        matched, unmatched, discrepancies = reconciler.reconcile(local, psp)
        
        assert len(discrepancies) == 1
        assert discrepancies[0].discrepancy_type == DiscrepancyType.STATUS_MISMATCH
    
    def test_reconcile_with_amount_tolerance(self):
        """Test reconciliation with amount tolerance."""
        now = datetime.utcnow()
        
        psp = [
            PSPTransaction(
                id="pi_001",
                amount=1000,
                currency="USD",
                status="captured",
                created_at=now,
            ),
        ]
        
        local = [
            LocalTransaction(
                id="local_001",
                provider_transaction_id="pi_001",
                amount=1005,  # 5 cents difference
                currency="USD",
                status="captured",
                captured_amount=1005,
                refunded_amount=0,
                created_at=now,
                updated_at=now,
            ),
        ]
        
        # Without tolerance - should have discrepancy
        reconciler = Reconciler(amount_tolerance=0)
        _, _, discrepancies = reconciler.reconcile(local, psp)
        assert len(discrepancies) == 1
        
        # With tolerance - should match
        reconciler = Reconciler(amount_tolerance=10)
        matched, unmatched, discrepancies = reconciler.reconcile(local, psp)
        assert len(matched) == 1
        assert len(discrepancies) == 0


class TestReportGenerator:
    """Tests for the ReportGenerator class."""
    
    def test_to_json_summary(self):
        """Test JSON summary generation."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_report_001",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            created_at=now,
            completed_at=now,
            total_local_records=100,
            total_psp_records=100,
            total_matched=95,
            total_unmatched=3,
            total_discrepancies=2,
        )
        
        generator = ReportGenerator(report)
        json_output = generator.to_json(include_details=False)
        
        assert "test_report_001" in json_output
        assert "95" in json_output
        assert "completed" in json_output
    
    def test_to_json_with_details(self):
        """Test JSON generation with full details."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_report_002",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            matched_records=[
                MatchedRecord(
                    local_id="local_001",
                    psp_id="pi_001",
                    amount=1000,
                    currency="USD",
                    status="captured",
                ),
            ],
            unmatched_records=[
                UnmatchedRecord(
                    source="psp",
                    transaction_id="pi_002",
                    amount=2000,
                    currency="USD",
                    status="captured",
                    created_at=now,
                    reason=DiscrepancyType.MISSING_IN_LOCAL,
                ),
            ],
        )
        
        generator = ReportGenerator(report)
        json_output = generator.to_json(include_details=True)
        
        assert "matched_records" in json_output
        assert "unmatched_records" in json_output
        assert "local_001" in json_output
        assert "pi_002" in json_output
    
    def test_to_csv(self):
        """Test CSV generation."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_report_003",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            matched_records=[
                MatchedRecord(
                    local_id="local_001",
                    psp_id="pi_001",
                    amount=1000,
                    currency="USD",
                    status="captured",
                ),
            ],
        )
        
        generator = ReportGenerator(report)
        csv_output = generator.to_csv(record_type="matched")
        
        assert "local_001" in csv_output
        assert "pi_001" in csv_output
        assert "1000" in csv_output
    
    def test_to_summary_text(self):
        """Test text summary generation."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_report_004",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            total_local_records=100,
            total_psp_records=100,
            total_matched=95,
        )
        
        generator = ReportGenerator(report)
        text_output = generator.to_summary_text()
        
        assert "RECONCILIATION REPORT SUMMARY" in text_output
        assert "test_report_004" in text_output
        assert "95" in text_output


class TestReconciliationService:
    """Tests for the ReconciliationService class."""
    
    async def test_fetch_local_transactions(self, db_session):
        """Test fetching local transactions for reconciliation."""
        # Create some test payments
        now = datetime.utcnow()
        
        payment1 = Payment(
            amount=1000,
            currency="USD",
            status=PaymentStatus.CAPTURED.value,
            provider="stripe",
            provider_transaction_id="pi_test_001",
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
        payment2 = Payment(
            amount=2000,
            currency="USD",
            status=PaymentStatus.AUTHORIZED.value,
            provider="stripe",
            provider_transaction_id="pi_test_002",
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=2),
        )
        
        db_session.add(payment1)
        db_session.add(payment2)
        await db_session.flush()
        
        service = ReconciliationService(db_session)
        
        transactions = await service.fetch_local_transactions(
            start_time=now - timedelta(days=1),
            end_time=now,
            provider="stripe",
        )
        
        assert len(transactions) == 2
        assert transactions[0].provider_transaction_id == "pi_test_002"
        assert transactions[1].provider_transaction_id == "pi_test_001"
    
    async def test_run_reconciliation_with_mock_psp(self, db_session):
        """Test running reconciliation with mocked PSP fetcher."""
        now = datetime.utcnow()
        
        # Create a local payment
        payment = Payment(
            amount=1000,
            currency="USD",
            status=PaymentStatus.CAPTURED.value,
            provider="stripe",
            provider_transaction_id="pi_mock_001",
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
        db_session.add(payment)
        await db_session.flush()
        
        # Create mock PSP fetcher
        mock_fetcher = MagicMock()
        mock_fetcher.fetch_transactions.return_value = [
            PSPTransaction(
                id="pi_mock_001",
                amount=1000,
                currency="USD",
                status="captured",
                created_at=now - timedelta(hours=1),
            ),
        ]
        
        service = ReconciliationService(db_session, psp_fetcher=mock_fetcher)
        
        request = ReconciliationRequest(
            start_time=now - timedelta(days=1),
            end_time=now,
            provider="stripe",
        )
        
        report = await service.run_reconciliation(request)
        
        assert report.status == ReconciliationStatus.COMPLETED
        assert report.total_local_records == 1
        assert report.total_psp_records == 1
        assert report.total_matched == 1
        assert report.total_unmatched == 0
        assert report.total_discrepancies == 0
    
    async def test_run_reconciliation_with_discrepancies(self, db_session):
        """Test reconciliation that finds discrepancies."""
        now = datetime.utcnow()
        
        # Create a local payment with different amount
        payment = Payment(
            amount=1500,  # Different from PSP
            currency="USD",
            status=PaymentStatus.CAPTURED.value,
            provider="stripe",
            provider_transaction_id="pi_mock_002",
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
        db_session.add(payment)
        await db_session.flush()
        
        # Create mock PSP fetcher with different amount
        mock_fetcher = MagicMock()
        mock_fetcher.fetch_transactions.return_value = [
            PSPTransaction(
                id="pi_mock_002",
                amount=1000,  # Different from local
                currency="USD",
                status="captured",
                created_at=now - timedelta(hours=1),
            ),
        ]
        
        service = ReconciliationService(db_session, psp_fetcher=mock_fetcher)
        
        request = ReconciliationRequest(
            start_time=now - timedelta(days=1),
            end_time=now,
            provider="stripe",
        )
        
        report = await service.run_reconciliation(request)
        
        assert report.status == ReconciliationStatus.COMPLETED
        assert report.total_discrepancies == 1
        assert report.discrepancy_records[0].discrepancy_type == DiscrepancyType.AMOUNT_MISMATCH
    
    def test_generate_report_formats(self, db_session):
        """Test report generation in different formats."""
        now = datetime.utcnow()
        
        report = ReconciliationReport(
            id="test_report",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            total_local_records=10,
            total_psp_records=10,
            total_matched=10,
        )
        
        # Need to use sync part of the service for this test
        service = ReconciliationService.__new__(ReconciliationService)
        
        json_output = service.generate_report(report, format="json")
        assert "test_report" in json_output
        
        text_output = service.generate_report(report, format="text")
        assert "RECONCILIATION REPORT SUMMARY" in text_output


class TestReconciliationModels:
    """Tests for reconciliation models."""
    
    def test_psp_transaction_model(self):
        """Test PSPTransaction model."""
        now = datetime.utcnow()
        txn = PSPTransaction(
            id="pi_001",
            amount=1000,
            currency="USD",
            status="captured",
            created_at=now,
        )
        
        assert txn.id == "pi_001"
        assert txn.amount == 1000
        assert txn.metadata == {}
    
    def test_local_transaction_model(self):
        """Test LocalTransaction model."""
        now = datetime.utcnow()
        txn = LocalTransaction(
            id="local_001",
            provider_transaction_id="pi_001",
            amount=1000,
            currency="USD",
            status="captured",
            created_at=now,
            updated_at=now,
        )
        
        assert txn.id == "local_001"
        assert txn.captured_amount == 0
    
    def test_reconciliation_report_summary(self):
        """Test ReconciliationReport summary generation."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_001",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            total_local_records=100,
            total_psp_records=100,
            total_matched=95,
            total_unmatched=3,
            total_discrepancies=2,
        )
        
        summary = report.to_summary_dict()
        
        assert summary["id"] == "test_001"
        assert summary["status"] == "completed"
        assert summary["statistics"]["match_rate"] == "95.00%"
    
    def test_reconciliation_report_full(self):
        """Test ReconciliationReport full export."""
        now = datetime.utcnow()
        report = ReconciliationReport(
            id="test_002",
            status=ReconciliationStatus.COMPLETED,
            provider="stripe",
            start_time=now - timedelta(days=1),
            end_time=now,
            matched_records=[
                MatchedRecord(
                    local_id="local_001",
                    psp_id="pi_001",
                    amount=1000,
                    currency="USD",
                    status="captured",
                ),
            ],
        )
        
        full = report.to_full_dict()
        
        assert len(full["matched_records"]) == 1
        assert full["matched_records"][0]["local_id"] == "local_001"
