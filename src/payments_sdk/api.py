import os
import re
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, Any, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from .connectors.base import PaymentRequest, PaymentResponse, ThreeDSCompleteRequest
from .connectors.stripe_connector import StripeConnector
from .database import get_db, init_db, close_db
from .services import PaymentService
from .auth import verify_api_key, limiter

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for database initialization."""
    # Initialize database on startup
    try:
        await init_db()
        logger.info("Database initialized on startup")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    yield
    
    # Cleanup on shutdown
    await close_db()
    logger.info("Database connection closed on shutdown")


app = FastAPI(title="Payments Connector - Reference API", lifespan=lifespan)

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

# Include reconciliation router - import here to avoid circular dependency
from .reconciliation.api import router as reconciliation_router
app.include_router(reconciliation_router)

allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
allowed_origins = [origin.strip() for origin in allowed_origins if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else [],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["X-Provider", "Authorization", "Content-Type", "X-Idempotency-Key"],
)


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


@app.post("/payments")
@limiter.limit("10/minute")
async def create_payment(
    request: Request,
    body: CreatePaymentBody,
    db: AsyncSession = Depends(get_db),
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: Optional[str] = Header(default=None)
):
    connector = get_connector(x_provider)
    idempotency = x_idempotency_key or body.idempotency_key
    if not idempotency:
        raise HTTPException(status_code=400, detail="Idempotency key is required")
    
    # Initialize payment service
    payment_service = PaymentService(db)
    
    # Check for idempotent request
    body_data = body.model_dump()
    body_data['payment_method'] = body.payment_method.model_dump(exclude_none=True)
    
    try:
        cached_response = await payment_service.check_idempotency(
            idempotency_key=idempotency,
            endpoint="/payments",
            request_data=body_data,
        )
        if cached_response:
            return cached_response
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    # Process new payment
    req = PaymentRequest(**body_data)
    resp: PaymentResponse = connector.authorize(req)
    
    # Persist payment
    payment = await payment_service.create_payment(
        request=req,
        provider_response=resp,
        provider=x_provider or "stripe",
        idempotency_key=idempotency,
    )
    
    result = resp.model_dump()
    result['internal_payment_id'] = payment.id
    return result


@app.post("/payments/{payment_id}/capture")
@limiter.limit("10/minute")
async def capture_payment(
    request: Request,
    payment_id: str,
    body: CaptureRefundBody,
    db: AsyncSession = Depends(get_db),
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    
    # Initialize payment service
    payment_service = PaymentService(db)
    
    # Check for idempotent request
    request_data = {"payment_id": validated_payment_id, "amount": body.amount}
    try:
        cached_response = await payment_service.check_idempotency(
            idempotency_key=x_idempotency_key,
            endpoint=f"/payments/{validated_payment_id}/capture",
            request_data=request_data,
        )
        if cached_response:
            return cached_response
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    # Process capture
    resp = connector.capture(validated_payment_id, body.amount)
    
    # Persist capture
    await payment_service.capture_payment(
        provider_transaction_id=validated_payment_id,
        amount=body.amount,
        provider_response=resp,
        idempotency_key=x_idempotency_key,
    )
    
    return resp.model_dump()


@app.post("/payments/{payment_id}/refund")
@limiter.limit("10/minute")
async def refund_payment(
    request: Request,
    payment_id: str,
    body: CaptureRefundBody,
    db: AsyncSession = Depends(get_db),
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    
    # Initialize payment service
    payment_service = PaymentService(db)
    
    # Check for idempotent request
    request_data = {"payment_id": validated_payment_id, "amount": body.amount}
    try:
        cached_response = await payment_service.check_idempotency(
            idempotency_key=x_idempotency_key,
            endpoint=f"/payments/{validated_payment_id}/refund",
            request_data=request_data,
        )
        if cached_response:
            return cached_response
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    # Process refund
    resp = connector.refund(validated_payment_id, body.amount)
    
    # Persist refund
    try:
        await payment_service.refund_payment(
            provider_transaction_id=validated_payment_id,
            amount=body.amount,
            provider_response=resp,
            idempotency_key=x_idempotency_key,
        )
    except ValueError as e:
        logger.warning(f"Could not persist refund: {e}")
    
    return resp.model_dump()


@app.post("/payments/{payment_id}/void")
@limiter.limit("10/minute")
async def void_payment(
    request: Request,
    payment_id: str,
    db: AsyncSession = Depends(get_db),
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: str = Header(...)
):
    validated_payment_id = validate_payment_id(payment_id)
    connector = get_connector(x_provider)
    
    # Initialize payment service
    payment_service = PaymentService(db)
    
    # Check for idempotent request
    request_data = {"payment_id": validated_payment_id}
    try:
        cached_response = await payment_service.check_idempotency(
            idempotency_key=x_idempotency_key,
            endpoint=f"/payments/{validated_payment_id}/void",
            request_data=request_data,
        )
        if cached_response:
            return cached_response
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    # Process void
    resp = connector.void(validated_payment_id)
    
    # Persist void
    try:
        await payment_service.void_payment(
            provider_transaction_id=validated_payment_id,
            provider_response=resp,
            idempotency_key=x_idempotency_key,
        )
    except ValueError as e:
        logger.warning(f"Could not persist void: {e}")
    
    return resp.model_dump()


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
    db: AsyncSession = Depends(get_db),
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
    
    # Initialize payment service
    payment_service = PaymentService(db)
    
    # Check for idempotent request
    request_data = {
        "payment_id": validated_payment_id,
        "authentication_result": body.authentication_result if body else None,
    }
    try:
        cached_response = await payment_service.check_idempotency(
            idempotency_key=x_idempotency_key,
            endpoint=f"/payments/{validated_payment_id}/3ds/complete",
            request_data=request_data,
        )
        if cached_response:
            return cached_response
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    # Process 3DS completion
    authentication_result = body.authentication_result if body else None
    resp = connector.complete_3ds(validated_payment_id, authentication_result)
    
    # Persist 3DS completion
    try:
        await payment_service.update_payment_from_3ds(
            provider_transaction_id=validated_payment_id,
            provider_response=resp,
            idempotency_key=x_idempotency_key,
            is_initiation=False,
        )
    except ValueError as e:
        logger.warning(f"Could not persist 3DS completion: {e}")
    
    return resp.model_dump()


@app.get("/payments/{payment_id}")
@limiter.limit("30/minute")
async def get_payment(
    request: Request,
    payment_id: str,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Get payment details by internal payment ID.
    
    Returns the payment record including status, amounts, and metadata.
    """
    payment_service = PaymentService(db)
    payment = await payment_service.get_payment(payment_id)
    
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    return payment.to_dict()


@app.get("/payments/{payment_id}/history")
@limiter.limit("30/minute")
async def get_payment_history(
    request: Request,
    payment_id: str,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Get transaction history for a payment.
    
    Returns a list of all state transitions and operations performed on the payment.
    """
    payment_service = PaymentService(db)
    
    # First verify payment exists
    payment = await payment_service.get_payment(payment_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    history = await payment_service.get_payment_history(payment_id)
    return {"payment_id": payment_id, "history": history}


@app.get("/merchants/{merchant_id}/payments")
@limiter.limit("20/minute")
async def list_merchant_payments(
    request: Request,
    merchant_id: str,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    List payments for a merchant.
    
    Returns paginated list of payments associated with the merchant.
    """
    if limit > 100:
        limit = 100
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0
    
    payment_service = PaymentService(db)
    payments = await payment_service.list_payments_by_merchant(
        merchant_id=merchant_id,
        limit=limit,
        offset=offset,
    )
    
    return {
        "merchant_id": merchant_id,
        "payments": payments,
        "limit": limit,
        "offset": offset,
    }


@app.post("/webhooks/psp")
@limiter.limit("100/minute")
async def psp_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
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
    
    # Process webhook event and update payment state if applicable
    payment_service = PaymentService(db)
    
    if event.get("type") in ("payment_intent.succeeded", "payment_intent.payment_failed", 
                              "payment_intent.canceled", "charge.refunded"):
        try:
            payment_data = event.get("data", {}).get("object", {})
            provider_transaction_id = payment_data.get("id")
            
            if provider_transaction_id:
                payment = await payment_service.get_payment_by_provider_id(
                    provider_transaction_id
                )
                if payment:
                    # Map webhook event type to status
                    status_map = {
                        "payment_intent.succeeded": "captured",
                        "payment_intent.payment_failed": "failed",
                        "payment_intent.canceled": "voided",
                        "charge.refunded": "refunded",
                    }
                    new_status = status_map.get(event.get("type"), payment.status)
                    
                    # Update payment status from webhook
                    from .database import PaymentRepository, TransactionHistoryRepository
                    payment_repo = PaymentRepository(db)
                    history_repo = TransactionHistoryRepository(db)
                    
                    await payment_repo.update_status(
                        payment=payment,
                        new_status=new_status,
                    )
                    await history_repo.create(
                        payment_id=payment.id,
                        action=f"webhook_{event.get('type')}",
                        previous_status=payment.status,
                        new_status=new_status,
                        action_metadata={"event_id": event.get("id")},
                    )
                    logger.info(
                        f"Updated payment {payment.id} status to {new_status} from webhook"
                    )
        except Exception as e:
            logger.warning(f"Failed to process webhook event: {e}")
    
    return {"accepted": True, "event": event}