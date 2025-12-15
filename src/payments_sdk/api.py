from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional
from .connectors.base import PaymentRequest, PaymentResponse
from .connectors.stripe_connector import StripeConnector

app = FastAPI(title="Payments Connector - Reference API")

# Very small registry of connectors — in real project this would be pluggable
CONNECTORS = {
    "stripe": StripeConnector()
}

class CreatePaymentBody(BaseModel):
    amount: int
    currency: str
    payment_method: dict
    merchant_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    intent: Optional[str] = "authorize"
    metadata: Optional[dict] = {}

@app.post("/payments")
async def create_payment(body: CreatePaymentBody, x_provider: Optional[str] = Header("stripe")):
    connector = CONNECTORS.get(x_provider)
    if not connector:
        raise HTTPException(status_code=400, detail="Provider not supported")
    req = PaymentRequest(**body.dict())
    resp: PaymentResponse = connector.authorize(req)
    return resp.dict()

@app.post("/payments/{payment_id}/capture")
async def capture_payment(payment_id: str, body: dict, x_provider: Optional[str] = Header("stripe")):
    connector = CONNECTORS.get(x_provider)
    if not connector:
        raise HTTPException(status_code=400, detail="Provider not supported")
    amount = int(body.get("amount", 0))
    resp = connector.capture(payment_id, amount)
    return resp.dict()

@app.post("/payments/{payment_id}/refund")
async def refund_payment(payment_id: str, body: dict, x_provider: Optional[str] = Header("stripe")):
    connector = CONNECTORS.get(x_provider)
    if not connector:
        raise HTTPException(status_code=400, detail="Provider not supported")
    amount = int(body.get("amount", 0))
    resp = connector.refund(payment_id, amount)
    return resp.dict()

@app.post("/webhooks/psp")
async def psp_webhook(request: Request, x_provider: Optional[str] = Header("stripe")):
    connector = CONNECTORS.get(x_provider)
    if not connector:
        raise HTTPException(status_code=400, detail="Provider not supported")
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    try:
        event = connector.parse_webhook(headers, body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    # In a real system we would enqueue a normalized event for processing
    return {"accepted": True, "event": event}