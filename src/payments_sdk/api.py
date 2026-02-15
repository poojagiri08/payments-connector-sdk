import os
import re
import logging
from fastapi import FastAPI, Request, Header, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .connectors.base import PaymentRequest, PaymentResponse
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
    if api_key != expected_key:
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


class CreatePaymentBody(BaseModel):
    amount: int = Field(..., gt=0, le=MAX_AMOUNT, description="Amount in minor units (e.g., cents)")
    currency: str = Field(..., min_length=3, max_length=3)
    payment_method: dict
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
    x_provider: Optional[str] = Header(default="stripe"),
    api_key: str = Depends(verify_api_key),
    x_idempotency_key: Optional[str] = Header(default=None)
):
    connector = get_connector(x_provider)
    idempotency = x_idempotency_key or body.idempotency_key
    if not idempotency:
        raise HTTPException(status_code=400, detail="Idempotency key is required")
    req = PaymentRequest(**body.model_dump())
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
        logger.error("Unexpected error processing webhook", exc_info=True)
        raise HTTPException(status_code=400, detail="Webhook processing failed")
    return {"accepted": True, "event": event}