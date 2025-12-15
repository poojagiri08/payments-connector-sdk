from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel

# Canonical models
class PaymentRequest(BaseModel):
    amount: int  # minor units
    currency: str
    merchant_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    payment_method: Dict[str, Any]
    intent: Optional[str] = "authorize"  # or "capture_immediate"
    metadata: Optional[Dict[str, Any]] = {}

class PaymentResponse(BaseModel):
    id: Optional[str]
    status: str  # authorized|captured|failed|pending_mfa|voided|refunded
    provider_transaction_id: Optional[str] = None
    provider_response_code: Optional[str] = None
    mfa: Optional[Dict[str, Any]] = None
    raw_provider_response: Optional[Dict[str, Any]] = None

class ConnectorBase(ABC):
    """
    Minimal connector interface. Implementations should be side-effect free
    until the method makes a network call to a PSP.
    """

    @abstractmethod
    def authorize(self, request: PaymentRequest) -> PaymentResponse:
        """
        Authorize a payment. Can return pending_mfa if 3DS/other flow required.
        """
        raise NotImplementedError

    @abstractmethod
    def capture(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        raise NotImplementedError

    @abstractmethod
    def refund(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        raise NotImplementedError

    @abstractmethod
    def void(self, provider_transaction_id: str) -> PaymentResponse:
        raise NotImplementedError

    @abstractmethod
    def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        """
        Validate and canonicalize a PSP webhook payload; return a canonical event dict.
        """
        raise NotImplementedError

    def health_check(self) -> Dict[str, Any]:
        return {"ok": True}