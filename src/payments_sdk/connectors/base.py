from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, model_validator
from enum import Enum

MAX_AMOUNT = 99999999


class LocalPaymentMethodType(str, Enum):
    """Supported local payment method types."""
    BANK_TRANSFER = "bank_transfer"
    BOLETO = "boleto"
    PIX = "pix"
    IDEAL = "ideal"
    SEPA_DEBIT = "sepa_debit"
    BANCONTACT = "bancontact"
    GIROPAY = "giropay"
    EPS = "eps"
    P24 = "p24"
    OXXO = "oxxo"
    SOFORT = "sofort"
    MULTIBANCO = "multibanco"
    ALIPAY = "alipay"
    WECHAT_PAY = "wechat_pay"
    BACS_DEBIT = "bacs_debit"
    BLIK = "blik"
    FPX = "fpx"
    GRABPAY = "grabpay"
    KLARNA = "klarna"
    AFTERPAY_CLEARPAY = "afterpay_clearpay"


# Region to supported payment methods mapping
REGION_PAYMENT_METHODS: Dict[str, List[LocalPaymentMethodType]] = {
    "BR": [LocalPaymentMethodType.BOLETO, LocalPaymentMethodType.PIX],
    "NL": [LocalPaymentMethodType.IDEAL, LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "BE": [LocalPaymentMethodType.BANCONTACT, LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "DE": [LocalPaymentMethodType.GIROPAY, LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "AT": [LocalPaymentMethodType.EPS, LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "PL": [LocalPaymentMethodType.P24, LocalPaymentMethodType.BLIK, LocalPaymentMethodType.KLARNA],
    "MX": [LocalPaymentMethodType.OXXO],
    "PT": [LocalPaymentMethodType.MULTIBANCO, LocalPaymentMethodType.SEPA_DEBIT],
    "CN": [LocalPaymentMethodType.ALIPAY, LocalPaymentMethodType.WECHAT_PAY],
    "GB": [LocalPaymentMethodType.BACS_DEBIT, LocalPaymentMethodType.KLARNA],
    "MY": [LocalPaymentMethodType.FPX, LocalPaymentMethodType.GRABPAY],
    "SG": [LocalPaymentMethodType.GRABPAY],
    "ES": [LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "FR": [LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "IT": [LocalPaymentMethodType.SEPA_DEBIT, LocalPaymentMethodType.SOFORT, LocalPaymentMethodType.KLARNA],
    "US": [LocalPaymentMethodType.BANK_TRANSFER, LocalPaymentMethodType.KLARNA, LocalPaymentMethodType.AFTERPAY_CLEARPAY],
    "AU": [LocalPaymentMethodType.AFTERPAY_CLEARPAY],
    "NZ": [LocalPaymentMethodType.AFTERPAY_CLEARPAY],
}

# Payment methods that support delayed/async confirmation
ASYNC_PAYMENT_METHODS: frozenset = frozenset([
    LocalPaymentMethodType.BOLETO,
    LocalPaymentMethodType.OXXO,
    LocalPaymentMethodType.MULTIBANCO,
    LocalPaymentMethodType.BANK_TRANSFER,
    LocalPaymentMethodType.BACS_DEBIT,
])

# Payment methods that require redirect flow
REDIRECT_PAYMENT_METHODS: frozenset = frozenset([
    LocalPaymentMethodType.IDEAL,
    LocalPaymentMethodType.BANCONTACT,
    LocalPaymentMethodType.GIROPAY,
    LocalPaymentMethodType.EPS,
    LocalPaymentMethodType.P24,
    LocalPaymentMethodType.SOFORT,
    LocalPaymentMethodType.ALIPAY,
    LocalPaymentMethodType.WECHAT_PAY,
    LocalPaymentMethodType.FPX,
    LocalPaymentMethodType.GRABPAY,
    LocalPaymentMethodType.KLARNA,
    LocalPaymentMethodType.AFTERPAY_CLEARPAY,
    LocalPaymentMethodType.BLIK,
])


class BankDetails(BaseModel):
    """Bank details for bank transfer and direct debit payment methods."""
    bank_code: Optional[str] = Field(default=None, max_length=20)
    bank_name: Optional[str] = Field(default=None, max_length=100)
    iban: Optional[str] = Field(default=None, max_length=34)
    bic: Optional[str] = Field(default=None, max_length=11)
    account_number: Optional[str] = Field(default=None, max_length=30)
    routing_number: Optional[str] = Field(default=None, max_length=20)
    sort_code: Optional[str] = Field(default=None, max_length=10)


class CustomerDetails(BaseModel):
    """Customer details required for some local payment methods."""
    name: Optional[str] = Field(default=None, max_length=200)
    email: Optional[str] = Field(default=None, max_length=254)
    phone: Optional[str] = Field(default=None, max_length=20)
    tax_id: Optional[str] = Field(default=None, max_length=20)
    address_line1: Optional[str] = Field(default=None, max_length=200)
    address_line2: Optional[str] = Field(default=None, max_length=200)
    city: Optional[str] = Field(default=None, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    country: Optional[str] = Field(default=None, min_length=2, max_length=2)


class LocalPaymentMethod(BaseModel):
    """
    Schema for local payment methods with type-specific fields.
    
    Different payment methods require different fields:
    - Bank transfers: bank_details with IBAN/account info
    - Boleto/OXXO: customer details (name, email, tax_id)
    - iDEAL: bank_code for the selected bank
    - SEPA: IBAN and mandate info
    - Redirect methods: return_url for redirect flow
    """
    type: LocalPaymentMethodType = Field(..., description="Type of local payment method")
    bank_details: Optional[BankDetails] = Field(default=None, description="Bank account details")
    customer: Optional[CustomerDetails] = Field(default=None, description="Customer information")
    return_url: Optional[str] = Field(default=None, max_length=2048, description="URL to redirect after payment")
    mandate_id: Optional[str] = Field(default=None, max_length=255, description="SEPA mandate ID")
    expires_at: Optional[str] = Field(default=None, description="Expiration timestamp (ISO 8601)")
    description: Optional[str] = Field(default=None, max_length=500, description="Payment description")

    @model_validator(mode='after')
    def validate_required_fields(self) -> 'LocalPaymentMethod':
        """Validate that required fields are present based on payment method type."""
        pm_type = self.type

        # Validate redirect URL for redirect-based methods
        if pm_type in REDIRECT_PAYMENT_METHODS and not self.return_url:
            raise ValueError(f"{pm_type.value} requires return_url for redirect flow")

        # Validate SEPA debit requirements
        if pm_type == LocalPaymentMethodType.SEPA_DEBIT:
            if not self.bank_details or not self.bank_details.iban:
                raise ValueError("SEPA debit requires bank_details with IBAN")

        # Validate Boleto requirements
        if pm_type == LocalPaymentMethodType.BOLETO:
            if not self.customer or not self.customer.name or not self.customer.tax_id:
                raise ValueError("Boleto requires customer name and tax_id (CPF/CNPJ)")

        # Validate PIX requirements
        if pm_type == LocalPaymentMethodType.PIX:
            if not self.customer or not self.customer.email:
                raise ValueError("PIX requires customer email")

        # Validate iDEAL requirements
        if pm_type == LocalPaymentMethodType.IDEAL:
            if not self.bank_details or not self.bank_details.bank_code:
                raise ValueError("iDEAL requires bank_code")

        # Validate BACS debit requirements
        if pm_type == LocalPaymentMethodType.BACS_DEBIT:
            if not self.bank_details or not self.bank_details.sort_code or not self.bank_details.account_number:
                raise ValueError("BACS debit requires sort_code and account_number")

        return self


def validate_region_payment_method(
    region: str,
    payment_method_type: LocalPaymentMethodType
) -> bool:
    """
    Validate that a payment method is supported in a given region.
    
    Args:
        region: ISO 3166-1 alpha-2 country code
        payment_method_type: The local payment method type to validate
        
    Returns:
        True if the payment method is supported in the region
        
    Raises:
        ValueError: If the payment method is not supported in the region
    """
    region_upper = region.upper()
    if region_upper not in REGION_PAYMENT_METHODS:
        raise ValueError(f"Region '{region}' does not have local payment methods configured")
    
    supported_methods = REGION_PAYMENT_METHODS[region_upper]
    if payment_method_type not in supported_methods:
        supported_names = [m.value for m in supported_methods]
        raise ValueError(
            f"Payment method '{payment_method_type.value}' is not supported in region '{region}'. "
            f"Supported methods: {', '.join(supported_names)}"
        )
    return True


def get_supported_payment_methods(region: str) -> List[LocalPaymentMethodType]:
    """
    Get list of supported local payment methods for a region.
    
    Args:
        region: ISO 3166-1 alpha-2 country code
        
    Returns:
        List of supported LocalPaymentMethodType values
    """
    region_upper = region.upper()
    return REGION_PAYMENT_METHODS.get(region_upper, [])


def is_async_payment_method(payment_method_type: LocalPaymentMethodType) -> bool:
    """Check if a payment method uses asynchronous confirmation."""
    return payment_method_type in ASYNC_PAYMENT_METHODS


def is_redirect_payment_method(payment_method_type: LocalPaymentMethodType) -> bool:
    """Check if a payment method requires redirect flow."""
    return payment_method_type in REDIRECT_PAYMENT_METHODS


# Canonical models
class PaymentRequest(BaseModel):
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3)
    merchant_id: Optional[str] = None
    idempotency_key: str = Field(..., min_length=1, max_length=255)
    payment_method: Dict[str, Any]
    local_payment_method: Optional[LocalPaymentMethod] = Field(
        default=None,
        description="Local payment method details (mutually exclusive with payment_method for local payments)"
    )
    intent: Optional[str] = Field(default="authorize", pattern="^(authorize|capture_immediate)$")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    region: Optional[str] = Field(default=None, min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code")

    @model_validator(mode='after')
    def validate_local_payment_region(self) -> 'PaymentRequest':
        """Validate local payment method against region if both are provided."""
        if self.local_payment_method and self.region:
            validate_region_payment_method(self.region, self.local_payment_method.type)
        return self



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
    status: str  # authorized|captured|failed|pending_mfa|voided|refunded|pending_redirect|pending_async
    provider_transaction_id: Optional[str] = None
    provider_response_code: Optional[str] = None
    mfa: Optional[MFAData] = Field(None, description="MFA data if 3DS/authentication required")
    raw_provider_response: Optional[Dict[str, Any]] = None
    redirect_url: Optional[str] = Field(default=None, description="URL to redirect customer for payment completion")
    payment_instructions: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Instructions for async payment methods (barcode, voucher number, etc.)"
    )
    expires_at: Optional[str] = Field(default=None, description="Payment expiration timestamp (ISO 8601)")


class LocalPaymentRequest(BaseModel):
    """
    Specialized request for local payment methods.
    Contains all required fields for processing local payments.
    """
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3)
    merchant_id: Optional[str] = None
    idempotency_key: str = Field(..., min_length=1, max_length=255)
    local_payment_method: LocalPaymentMethod = Field(..., description="Local payment method details")
    region: str = Field(..., min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    statement_descriptor: Optional[str] = Field(default=None, max_length=22, description="Statement descriptor")

    @model_validator(mode='after')
    def validate_region_support(self) -> 'LocalPaymentRequest':
        """Validate that the payment method is supported in the specified region."""
        validate_region_payment_method(self.region, self.local_payment_method.type)
        return self


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
    def process_local_payment(self, request: LocalPaymentRequest) -> PaymentResponse:
        """
        Process a local payment method (bank transfer, boleto, iDEAL, etc.).
        
        Returns PaymentResponse with:
        - status: 'pending_redirect' for redirect-based methods
        - status: 'pending_async' for async methods like boleto/OXXO
        - redirect_url: URL for customer to complete payment (redirect methods)
        - payment_instructions: Voucher/barcode info (async methods)
        """
        raise NotImplementedError

    def get_supported_local_payment_methods(self, region: Optional[str] = None) -> List[LocalPaymentMethodType]:
        """
        Get list of local payment methods supported by this connector.
        Optionally filter by region.
        
        Override this method to customize supported payment methods per connector.
        """
        if region:
            return get_supported_payment_methods(region)
        # Return all payment method types if no region specified
        return list(LocalPaymentMethodType)

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