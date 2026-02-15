from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

MAX_AMOUNT = 99999999

# Canonical models
class PaymentRequest(BaseModel):
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3)
    merchant_id: Optional[str] = None
    idempotency_key: str = Field(..., min_length=1, max_length=255)
    payment_method: Dict[str, Any]
    intent: Optional[str] = Field(default="authorize", pattern="^(authorize|capture_immediate)$")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

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