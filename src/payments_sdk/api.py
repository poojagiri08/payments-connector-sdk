import os
import re
import logging
import secrets
from fastapi import FastAPI, Request, Header, HTTPException, Depends, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, Any, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .connectors.base import (
    PaymentRequest,
    PaymentResponse,
    LocalPaymentRequest,
    LocalPaymentMethod,
    LocalPaymentMethodType,
    BankDetails,
    CustomerDetails,
    get_supported_payment_methods,
    validate_region_payment_method,
    ThreeDSCompleteRequest,
)
from .connectors.stripe_connector import StripeConnector

logger = logging.getLogger(__name__)

app = FastAPI(title="Payments Connector - Reference API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."}
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)

allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
allowed_origins = [origin.strip() for origin in allowed_origins if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else [],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["X-Provider", "Authorization", "Content-Type", "X-Idempotency-Key"],
)

security = HTTPBearer()


async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    api_key = credentials.credentials
    expected_key = os.getenv("API_KEY")
    if not expected_key:
        logger.error("API_KEY environment variable is not configured")
        raise HTTPException(status_code=500, detail="Server configuration error")
    if not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


def get_connector(x_provider: str = "stripe") -> StripeConnector:
    connectors = {
        "stripe": StripeConnector()
    }
    connector = connectors.get(x_provider)
    if not connector:
        raise HTTPException(status_code=400, detail="Provider not supported")
    return connector


PAYMENT_ID_PATTERN = re.compile(r'^pi_[a-zA-Z0-9]{24,}$')


def validate_payment_id(payment_id: str) -> str:
    if not PAYMENT_ID_PATTERN.match(payment_id):
        raise HTTPException(status_code=400, detail="Invalid payment ID format")
    return payment_id


MAX_AMOUNT = 99999999
MIN_AMOUNT = 1
MAX_DECIMAL_PLACES = 2

ALLOWED_PAYMENT_METHOD_FIELDS = frozenset(['token', 'type'])
MAX_METADATA_KEYS = 50
MAX_METADATA_KEY_LENGTH = 40
MAX_METADATA_VALUE_LENGTH = 500
MAX_METADATA_TOTAL_SIZE = 8192


class PaymentMethodModel(BaseModel):
    token: str = Field(..., min_length=1, max_length=255)
    type: Optional[str] = Field(default=None, max_length=50)

    @model_validator(mode='before')
    @classmethod
    def validate_allowed_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            extra_fields = set(values.keys()) - ALLOWED_PAYMENT_METHOD_FIELDS
            if extra_fields:
                raise ValueError(f'Unexpected fields in payment_method: {extra_fields}')
        return values


def validate_metadata(metadata: Optional[dict]) -> Optional[dict]:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        raise ValueError('metadata must be a dictionary')
    if len(metadata) > MAX_METADATA_KEYS:
        raise ValueError(f'metadata cannot have more than {MAX_METADATA_KEYS} keys')
    total_size = 0
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise ValueError('metadata keys must be strings')
        if len(key) > MAX_METADATA_KEY_LENGTH:
            raise ValueError(f'metadata key length cannot exceed {MAX_METADATA_KEY_LENGTH} characters')
        if not isinstance(value, (str, int, float, bool, type(None))):
            raise ValueError('metadata values must be strings, numbers, booleans, or null')
        value_str = str(value) if value is not None else ''
        if len(value_str) > MAX_METADATA_VALUE_LENGTH:
            raise ValueError(f'metadata value length cannot exceed {MAX_METADATA_VALUE_LENGTH} characters')
        total_size += len(key) + len(value_str)
    if total_size > MAX_METADATA_TOTAL_SIZE:
        raise ValueError(f'metadata total size cannot exceed {MAX_METADATA_TOTAL_SIZE} bytes')
    return metadata


class CreatePaymentBody(BaseModel):
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units (e.g., cents)")
    currency: str = Field(..., min_length=3, max_length=3)
    payment_method: PaymentMethodModel
    merchant_id: Optional[str] = None
    idempotency_key: str = Field(..., min_length=1, max_length=255)
    intent: Optional[str] = Field(default="authorize", pattern="^(authorize|capture_immediate)$")
    metadata: Optional[dict] = Field(default_factory=dict)

    @field_validator('amount')
    @classmethod
    def validate_amount(cls, v: int) -> int:
        if v <= 0:
            raise ValueError('Amount must be positive')
        if v > MAX_AMOUNT:
            raise ValueError(f'Amount must not exceed {MAX_AMOUNT}')
        return v

    @field_validator('currency')
    @classmethod
    def validate_currency(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError('Currency must contain only letters')
        return v.upper()

    @field_validator('metadata')
    @classmethod
    def validate_metadata_field(cls, v: Optional[dict]) -> Optional[dict]:
        return validate_metadata(v)


class CaptureRefundBody(BaseModel):
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units")

    @field_validator('amount')
    @classmethod
    def validate_amount(cls, v: int) -> int:
        if v <= 0:
            raise ValueError('Amount must be positive')
        if v > MAX_AMOUNT:
            raise ValueError(f'Amount must not exceed {MAX_AMOUNT}')
        return v


# API models for local payment methods
class BankDetailsModel(BaseModel):
    """Bank details for bank transfer and direct debit payment methods."""
    bank_code: Optional[str] = Field(default=None, max_length=20)
    bank_name: Optional[str] = Field(default=None, max_length=100)
    iban: Optional[str] = Field(default=None, max_length=34)
    bic: Optional[str] = Field(default=None, max_length=11)
    account_number: Optional[str] = Field(default=None, max_length=30)
    routing_number: Optional[str] = Field(default=None, max_length=20)
    sort_code: Optional[str] = Field(default=None, max_length=10)


class CustomerDetailsModel(BaseModel):
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


class LocalPaymentMethodModel(BaseModel):
    """Local payment method details."""
    type: str = Field(..., description="Type of local payment method")
    bank_details: Optional[BankDetailsModel] = Field(default=None)
    customer: Optional[CustomerDetailsModel] = Field(default=None)
    return_url: Optional[str] = Field(default=None, max_length=2048)
    mandate_id: Optional[str] = Field(default=None, max_length=255)
    expires_at: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None, max_length=500)

    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        valid_types = [t.value for t in LocalPaymentMethodType]
        if v not in valid_types:
            raise ValueError(f'Invalid payment method type. Valid types: {", ".join(valid_types)}')
        return v


class CreateLocalPaymentBody(BaseModel):
    """Request body for creating a local payment."""
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3)
    idempotency_key: str = Field(..., min_length=1, max_length=255)
    region: str = Field(..., min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code")
    local_payment_method: LocalPaymentMethodModel = Field(..., description="Local payment method details")
    merchant_id: Optional[str] = Field(default=None, max_length=255)
    metadata: Optional[dict] = Field(default_factory=dict)
    statement_descriptor: Optional[str] = Field(default=None, max_length=22)

    @field_validator('amount')
    @classmethod
    def validate_amount(cls, v: int) -> int:
        if v <= 0:
            raise ValueError('Amount must be positive')
        if v > MAX_AMOUNT:
            raise ValueError(f'Amount must not exceed {MAX_AMOUNT}')
        return v

    @field_validator('currency')
    @classmethod
    def validate_currency(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError('Currency must contain only letters')
        return v.upper()

    @field_validator('region')
    @classmethod
    def validate_region(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError('Region must contain only letters')
        return v.upper()

    @field_validator('metadata')
    @classmethod
    def validate_metadata_field(cls, v: Optional[dict]) -> Optional[dict]:
        return validate_metadata(v)


@app.post("/payments")
@limiter.limit("10/minute")
async def create_payment(
    request: Request,
    body: CreatePaymentBody,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: Optional[str] = Header(default=None)
):
    connector = get_connector(x_provider)
    idempotency = x_idempotency_key or body.idempotency_key
    if not idempotency:
        raise HTTPException(status_code=400, detail="Idempotency key is required")
    body_data = body.model_dump()
    body_data['payment_method'] = body.payment_method.model_dump(exclude_none=True)
    req = PaymentRequest(**body_data)
    resp: PaymentResponse = connector.authorize(req)
    return resp.model_dump()


@app.post("/payments/{payment_id}/capture")
@limiter.limit("10/minute")
async def capture_payment(
    request: Request,
    payment_id: str,
    body: CaptureRefundBody,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    resp = connector.capture(validated_payment_id, body.amount)
    return resp.model_dump()


@app.post("/payments/{payment_id}/refund")
@limiter.limit("10/minute")
async def refund_payment(
    request: Request,
    payment_id: str,
    body: CaptureRefundBody,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    resp = connector.refund(validated_payment_id, body.amount)
    return resp.model_dump()


@app.post("/payments/{payment_id}/void")
@limiter.limit("10/minute")
async def void_payment(
    request: Request,
    payment_id: str,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    resp = connector.void(validated_payment_id)
    return resp.model_dump()


@app.post("/payments/local")
@limiter.limit("10/minute")
async def create_local_payment(
    request: Request,
    body: CreateLocalPaymentBody,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: Optional[str] = Header(default=None)
):
    """
    Create a local payment using region-specific payment methods.
    
    Local payment methods include:
    - iDEAL (Netherlands)
    - SEPA Direct Debit (EU)
    - Boleto, PIX (Brazil)
    - Bancontact (Belgium)
    - giropay (Germany)
    - EPS (Austria)
    - P24 (Poland)
    - OXXO (Mexico)
    - And more...
    
    Returns:
    - For redirect methods: redirect_url to redirect customer
    - For async methods: payment_instructions with voucher/barcode info
    """
    connector = get_connector(x_provider)
    idempotency = x_idempotency_key or body.idempotency_key
    if not idempotency:
        raise HTTPException(status_code=400, detail="Idempotency key is required")
    
    # Validate region and payment method combination
    try:
        pm_type = LocalPaymentMethodType(body.local_payment_method.type)
        validate_region_payment_method(body.region, pm_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Build bank details if provided
    bank_details = None
    if body.local_payment_method.bank_details:
        bank_details = BankDetails(**body.local_payment_method.bank_details.model_dump())
    
    # Build customer details if provided
    customer = None
    if body.local_payment_method.customer:
        customer = CustomerDetails(**body.local_payment_method.customer.model_dump())
    
    # Build local payment method
    local_pm = LocalPaymentMethod(
        type=pm_type,
        bank_details=bank_details,
        customer=customer,
        return_url=body.local_payment_method.return_url,
        mandate_id=body.local_payment_method.mandate_id,
        expires_at=body.local_payment_method.expires_at,
        description=body.local_payment_method.description,
    )
    
    # Build request
    req = LocalPaymentRequest(
        amount=body.amount,
        currency=body.currency,
        merchant_id=body.merchant_id,
        idempotency_key=idempotency,
        local_payment_method=local_pm,
        region=body.region,
        metadata=body.metadata or {},
        statement_descriptor=body.statement_descriptor,
    )
    
    resp: PaymentResponse = connector.process_local_payment(req)
    return resp.model_dump()


@app.get("/payments/local/methods")
@limiter.limit("30/minute")
async def list_local_payment_methods(
    request: Request,
    region: Optional[str] = Query(default=None, min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code"),
    x_provider: Optional[str] = Header(default="stripe"),
):
    """
    List available local payment methods.
    
    Optionally filter by region to see which methods are supported in a specific country.
    """
    connector = get_connector(x_provider)
    
    if region:
        region = region.upper()
        methods = connector.get_supported_local_payment_methods(region)
    else:
        methods = connector.get_supported_local_payment_methods()
    
    return {
        "region": region,
        "payment_methods": [
            {
                "type": m.value,
                "name": m.value.replace("_", " ").title(),
            }
            for m in methods
        ]
    }


@app.get("/payments/{payment_id}/3ds")
@limiter.limit("20/minute")
async def get_3ds_challenge(
    request: Request,
    payment_id: str,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key)
):
    """
    Retrieve 3DS challenge data for a payment requiring MFA authentication.
    
    Returns challenge information including redirect URLs and client secrets
    needed for the frontend to complete the 3DS flow.
    """
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    resp = connector.get_3ds_challenge(validated_payment_id)
    return resp.model_dump()


@app.post("/payments/{payment_id}/3ds/complete")
@limiter.limit("10/minute")
async def complete_3ds_authentication(
    request: Request,
    payment_id: str,
    body: Optional[ThreeDSCompleteRequest] = None,
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    """
    Complete 3DS authentication for a payment.
    
    This endpoint should be called after the frontend has completed the 3DS challenge.
    It transitions the payment from pending_mfa to authorized (or captured/failed).
    """
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    authentication_result = body.authentication_result if body else None
    resp = connector.complete_3ds(validated_payment_id, authentication_result)
    return resp.model_dump()


@app.post("/webhooks/psp")
@limiter.limit("100/minute")
async def psp_webhook(
    request: Request,
    x_provider: Optional[str] = Header(default="stripe")
):
    connector = get_connector(x_provider)
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    try:
        event = connector.parse_webhook(headers, body)
    except ValueError as e:
        logger.warning(f"Webhook validation failed: {e}")
        raise HTTPException(status_code=400, detail="Webhook validation failed")
    except Exception:
        logger.error("Unexpected error processing webhook")
        raise HTTPException(status_code=400, detail="Webhook processing failed")
    return {"accepted": True, "event": event}