"""Simulator connector for testing payment flows without real PSP calls."""

import uuid
import time
import random
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .base import ConnectorBase, PaymentRequest, PaymentResponse

logger = logging.getLogger(__name__)


class SimulatorScenario(str, Enum):
    """Predefined test scenarios for the simulator."""
    SUCCESS = "success"
    FAILURE = "failure"
    REQUIRES_3DS = "requires_3ds"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    INVALID_CARD = "invalid_card"
    INSUFFICIENT_FUNDS = "insufficient_funds"


@dataclass
class SimulatedTransaction:
    """In-memory representation of a simulated transaction."""
    id: str
    amount: int
    currency: str
    status: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    captured_amount: int = 0
    refunded_amount: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    requires_3ds: bool = False
    three_ds_completed: bool = False


@dataclass
class SimulatorConfig:
    """Configuration for simulator behavior."""
    success_rate: float = 1.0  # 0.0 to 1.0
    three_ds_rate: float = 0.0  # Rate of 3DS challenges
    delay_ms: int = 0  # Simulated response delay in ms
    timeout_rate: float = 0.0  # Rate of timeout errors
    seed: Optional[int] = None  # Random seed for reproducibility


class SimulatorConnector(ConnectorBase):
    """
    Simulator connector for testing payment flows without making real PSP calls.
    
    Features:
    - In-memory transaction storage
    - Configurable success/failure rates
    - 3DS challenge simulation
    - Delayed response simulation
    - Special card numbers for specific scenarios
    """

    # Special card tokens for triggering specific behaviors
    CARD_SUCCESS = "sim_card_success"
    CARD_DECLINE = "sim_card_decline"
    CARD_3DS = "sim_card_3ds"
    CARD_INSUFFICIENT = "sim_card_insufficient"
    CARD_TIMEOUT = "sim_card_timeout"

    def __init__(self, config: Optional[SimulatorConfig] = None):
        """Initialize the simulator with optional configuration."""
        self.config = config or SimulatorConfig()
        self._transactions: Dict[str, SimulatedTransaction] = {}
        self._rng = random.Random(self.config.seed)
        logger.info("SimulatorConnector initialized")

    def _generate_id(self) -> str:
        """Generate a unique simulator transaction ID."""
        return f"sim_{uuid.uuid4().hex[:24]}"

    def _apply_delay(self) -> None:
        """Apply configured response delay."""
        if self.config.delay_ms > 0:
            time.sleep(self.config.delay_ms / 1000.0)

    def _should_timeout(self) -> bool:
        """Check if this request should simulate a timeout."""
        return self._rng.random() < self.config.timeout_rate

    def _should_succeed(self) -> bool:
        """Check if this request should succeed based on success rate."""
        return self._rng.random() < self.config.success_rate

    def _should_require_3ds(self) -> bool:
        """Check if this request should require 3DS."""
        return self._rng.random() < self.config.three_ds_rate

    def _determine_scenario(self, token: str) -> SimulatorScenario:
        """Determine scenario based on card token or random config."""
        card_scenarios = {
            self.CARD_SUCCESS: SimulatorScenario.SUCCESS,
            self.CARD_DECLINE: SimulatorScenario.FAILURE,
            self.CARD_3DS: SimulatorScenario.REQUIRES_3DS,
            self.CARD_INSUFFICIENT: SimulatorScenario.INSUFFICIENT_FUNDS,
            self.CARD_TIMEOUT: SimulatorScenario.TIMEOUT,
        }
        if token in card_scenarios:
            return card_scenarios[token]
        if self._should_timeout():
            return SimulatorScenario.TIMEOUT
        if not self._should_succeed():
            return SimulatorScenario.FAILURE
        if self._should_require_3ds():
            return SimulatorScenario.REQUIRES_3DS
        return SimulatorScenario.SUCCESS

    def authorize(self, request: PaymentRequest) -> PaymentResponse:
        """Authorize a simulated payment."""
        self._apply_delay()
        token = request.payment_method.get("token", "")
        scenario = self._determine_scenario(token)
        
        if scenario == SimulatorScenario.TIMEOUT:
            raise TimeoutError("Simulated timeout")
        
        txn_id = self._generate_id()
        
        if scenario == SimulatorScenario.FAILURE:
            return PaymentResponse(
                id=txn_id, status="failed", provider_transaction_id=txn_id,
                provider_response_code="declined",
                raw_provider_response={"error": "card_declined", "simulator": True}
            )
        
        if scenario == SimulatorScenario.INSUFFICIENT_FUNDS:
            return PaymentResponse(
                id=txn_id, status="failed", provider_transaction_id=txn_id,
                provider_response_code="insufficient_funds",
                raw_provider_response={"error": "insufficient_funds", "simulator": True}
            )
        
        requires_3ds = scenario == SimulatorScenario.REQUIRES_3DS
        status = "pending_mfa" if requires_3ds else "authorized"
        
        txn = SimulatedTransaction(
            id=txn_id, amount=request.amount, currency=request.currency,
            status=status, metadata=request.metadata or {}, requires_3ds=requires_3ds
        )
        self._transactions[txn_id] = txn
        
        mfa = None
        if requires_3ds:
            mfa = {"type": "3ds", "redirect_url": f"/payments/{txn_id}/3ds"}
        
        return PaymentResponse(
            id=txn_id, status=status, provider_transaction_id=txn_id,
            mfa=mfa, raw_provider_response={"simulator": True, "scenario": scenario.value}
        )

    def capture(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        """Capture a previously authorized payment."""
        self._apply_delay()
        txn = self._transactions.get(provider_transaction_id)
        
        if not txn:
            return PaymentResponse(
                id=None, status="failed", provider_transaction_id=provider_transaction_id,
                provider_response_code="not_found",
                raw_provider_response={"error": "transaction_not_found", "simulator": True}
            )
        
        if txn.status != "authorized":
            return PaymentResponse(
                id=txn.id, status="failed", provider_transaction_id=txn.id,
                provider_response_code="invalid_state",
                raw_provider_response={"error": f"cannot_capture_{txn.status}", "simulator": True}
            )
        
        txn.captured_amount = amount
        txn.status = "captured"
        
        return PaymentResponse(
            id=txn.id, status="captured", provider_transaction_id=txn.id,
            raw_provider_response={"simulator": True, "captured_amount": amount}
        )

    def refund(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        """Refund a captured payment."""
        self._apply_delay()
        txn = self._transactions.get(provider_transaction_id)
        
        if not txn:
            return PaymentResponse(
                id=None, status="failed", provider_transaction_id=provider_transaction_id,
                provider_response_code="not_found",
                raw_provider_response={"error": "transaction_not_found", "simulator": True}
            )
        
        if txn.status != "captured":
            return PaymentResponse(
                id=txn.id, status="failed", provider_transaction_id=txn.id,
                provider_response_code="invalid_state",
                raw_provider_response={"error": f"cannot_refund_{txn.status}", "simulator": True}
            )
        
        txn.refunded_amount += amount
        if txn.refunded_amount >= txn.captured_amount:
            txn.status = "refunded"
        else:
            txn.status = "partially_refunded"
        
        return PaymentResponse(
            id=txn.id, status=txn.status, provider_transaction_id=txn.id,
            raw_provider_response={"simulator": True, "refunded_amount": txn.refunded_amount}
        )

    def void(self, provider_transaction_id: str) -> PaymentResponse:
        """Void an authorized payment."""
        self._apply_delay()
        txn = self._transactions.get(provider_transaction_id)
        
        if not txn:
            return PaymentResponse(
                id=None, status="failed", provider_transaction_id=provider_transaction_id,
                provider_response_code="not_found",
                raw_provider_response={"error": "transaction_not_found", "simulator": True}
            )
        
        if txn.status not in ("authorized", "pending_mfa"):
            return PaymentResponse(
                id=txn.id, status="failed", provider_transaction_id=txn.id,
                provider_response_code="invalid_state",
                raw_provider_response={"error": f"cannot_void_{txn.status}", "simulator": True}
            )
        
        txn.status = "voided"
        return PaymentResponse(
            id=txn.id, status="voided", provider_transaction_id=txn.id,
            raw_provider_response={"simulator": True}
        )

    def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        """Parse a simulated webhook payload."""
        import json
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise ValueError("Invalid webhook payload")
        
        event_type = payload.get("type", "unknown")
        txn_id = payload.get("transaction_id")
        
        return {
            "type": event_type,
            "provider": "simulator",
            "payload": {"transaction_id": txn_id, "data": payload}
        }

    def complete_3ds(self, provider_transaction_id: str, success: bool = True) -> PaymentResponse:
        """Complete a 3DS challenge (simulator-specific method)."""
        txn = self._transactions.get(provider_transaction_id)
        
        if not txn:
            return PaymentResponse(
                id=None, status="failed", provider_transaction_id=provider_transaction_id,
                provider_response_code="not_found",
                raw_provider_response={"error": "transaction_not_found", "simulator": True}
            )
        
        if not txn.requires_3ds or txn.three_ds_completed:
            return PaymentResponse(
                id=txn.id, status="failed", provider_transaction_id=txn.id,
                provider_response_code="invalid_state",
                raw_provider_response={"error": "3ds_not_required_or_completed", "simulator": True}
            )
        
        txn.three_ds_completed = True
        if success:
            txn.status = "authorized"
            return PaymentResponse(
                id=txn.id, status="authorized", provider_transaction_id=txn.id,
                raw_provider_response={"simulator": True, "three_ds": "completed"}
            )
        else:
            txn.status = "failed"
            return PaymentResponse(
                id=txn.id, status="failed", provider_transaction_id=txn.id,
                provider_response_code="3ds_failed",
                raw_provider_response={"simulator": True, "three_ds": "failed"}
            )

    def get_transaction(self, transaction_id: str) -> Optional[SimulatedTransaction]:
        """Get a transaction from in-memory storage (for testing)."""
        return self._transactions.get(transaction_id)

    def get_all_transactions(self) -> Dict[str, SimulatedTransaction]:
        """Get all transactions (for testing)."""
        return dict(self._transactions)

    def clear_transactions(self) -> None:
        """Clear all stored transactions (for test cleanup)."""
        self._transactions.clear()

    def health_check(self) -> Dict[str, Any]:
        """Return health status of the simulator."""
        return {
            "ok": True,
            "provider": "simulator",
            "transaction_count": len(self._transactions),
            "config": {
                "success_rate": self.config.success_rate,
                "three_ds_rate": self.config.three_ds_rate,
                "delay_ms": self.config.delay_ms,
                "timeout_rate": self.config.timeout_rate,
            }
        }
