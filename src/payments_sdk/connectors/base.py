from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
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


class ThreeDSChallengeData(BaseModel):
    """3DS challenge data structure for MFA authentication"""
    acs_url: Optional[str] = Field(None, description="Access Control Server URL for 3DS redirect")
    client_secret: Optional[str] = Field(None, description="Client secret for frontend 3DS handling")
    transaction_id: Optional[str] = Field(None, description="3DS transaction identifier")
    version: Optional[str] = Field(None, description="3DS version (1.0, 2.0, 2.1, etc.)")


class MFAData(BaseModel):
    """MFA/3DS data structure included in PaymentResponse when authentication is required"""
    type: str = Field(..., description="Type of MFA required (e.g., '3ds')")
    redirect_url: Optional[str] = Field(None, description="URL path for 3DS challenge retrieval")
    challenge_data: Optional[ThreeDSChallengeData] = Field(None, description="3DS specific challenge data")
    next_action_type: Optional[str] = Field(None, description="Provider-specific next action type")


class ThreeDSChallengeResponse(BaseModel):
    """Response for GET /payments/{payment_id}/3ds endpoint"""
    payment_id: str = Field(..., description="Payment identifier")
    status: str = Field(..., description="Current 3DS challenge status")
    mfa: Optional[MFAData] = Field(None, description="MFA data with 3DS challenge details")
    raw_provider_response: Optional[Dict[str, Any]] = Field(None, description="Sanitized provider response")


class ThreeDSCompleteRequest(BaseModel):
    """Request body for POST /payments/{payment_id}/3ds/complete endpoint"""
    authentication_result: Optional[str] = Field(
        None, 
        description="Optional authentication result from frontend (for certain 3DS flows)"
    )


class PaymentResponse(BaseModel):
    id: Optional[str]
    status: str  # authorized|captured|failed|pending_mfa|voided|refunded
    provider_transaction_id: Optional[str] = None
    provider_response_code: Optional[str] = None
    mfa: Optional[MFAData] = Field(None, description="MFA data if 3DS/authentication required")
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

    @abstractmethod
    def get_3ds_challenge(self, payment_id: str) -> ThreeDSChallengeResponse:
        """
        Retrieve 3DS challenge data for a payment that requires MFA.
        Returns challenge information needed for frontend to complete 3DS flow.
        """
        raise NotImplementedError

    @abstractmethod
    def complete_3ds(self, payment_id: str, authentication_result: Optional[str] = None) -> PaymentResponse:
        """
        Complete 3DS authentication for a payment.
        This confirms the PaymentIntent after 3DS challenge is completed.
        Transitions payment from pending_mfa to authorized (or captured/failed).
        """
        raise NotImplementedError

    def health_check(self) -> Dict[str, Any]:
        return {"ok": True}