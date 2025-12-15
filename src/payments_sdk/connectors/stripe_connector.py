import os
from typing import Dict, Any
import stripe
from .base import ConnectorBase, PaymentRequest, PaymentResponse

stripe.api_key = os.getenv("STRIPE_API_KEY", "")

class StripeConnector(ConnectorBase):
    """
    Minimal Stripe connector using stripe-python. This example focuses on card payment
    flows using PaymentIntents. It expects that the merchant frontend obtains a
    payment method token / payment_method id from Stripe.js and passes it to the server.
    """

    def __init__(self):
        if not stripe.api_key:
            # connector will still exist but will error on operations if not configured
            pass

    def authorize(self, request: PaymentRequest) -> PaymentResponse:
        # Use PaymentIntent with capture_method=manual for authorization-only
        try:
            capture_method = "manual" if request.intent == "authorize" else "automatic"
            pi = stripe.PaymentIntent.create(
                amount=request.amount,
                currency=request.currency.lower(),
                payment_method=request.payment_method.get("token"),
                confirmation_method="manual",
                confirm=True,
                capture_method=capture_method,
                metadata=request.metadata or {},
            )
            status_map = {
                "requires_capture": "authorized",
                "requires_action": "pending_mfa",
                "succeeded": "captured",
                "requires_payment_method": "failed",
            }
            status = status_map.get(pi.status, "pending")
            mfa = None
            if pi.status == "requires_action":
                # 3DS required — provide client_secret for frontend to complete 3DS
                mfa = {"type": "3ds", "client_secret": pi.client_secret}
            return PaymentResponse(
                id=pi.id,
                status=status,
                provider_transaction_id=pi.id,
                raw_provider_response=pi.to_dict(),
                mfa=mfa,
            )
        except stripe.error.StripeError as e:
            # map Stripe errors to canonical response
            return PaymentResponse(id=None, status="failed", raw_provider_response={"error": str(e)})

    def capture(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        try:
            captured = stripe.PaymentIntent.capture(provider_transaction_id, amount_to_capture=amount)
            return PaymentResponse(
                id=captured.id, status="captured", provider_transaction_id=captured.id, raw_provider_response=captured.to_dict()
            )
        except stripe.error.StripeError as e:
            return PaymentResponse(id=None, status="failed", raw_provider_response={"error": str(e)})

    def refund(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        try:
            r = stripe.Refund.create(payment_intent=provider_transaction_id, amount=amount)
            return PaymentResponse(id=r.id, status="refunded", provider_transaction_id=provider_transaction_id, raw_provider_response=r.to_dict())
        except stripe.error.StripeError as e:
            return PaymentResponse(id=None, status="failed", raw_provider_response={"error": str(e)})

    def void(self, provider_transaction_id: str) -> PaymentResponse:
        # Stripe: cancel an uncaptured PaymentIntent
        try:
            pi = stripe.PaymentIntent.cancel(provider_transaction_id)
            return PaymentResponse(id=pi.id, status="voided", provider_transaction_id=pi.id, raw_provider_response=pi.to_dict())
        except stripe.error.StripeError as e:
            return PaymentResponse(id=None, status="failed", raw_provider_response={"error": str(e)})

    def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        # Use STRIPE_WEBHOOK_SECRET env var if you want to verify signature
        webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        if webhook_secret:
            sig_header = headers.get("stripe-signature", "")
            try:
                event = stripe.Webhook.construct_event(payload=body, sig_header=sig_header, secret=webhook_secret)
            except Exception as e:
                raise ValueError("Invalid webhook signature") from e
        else:
            # best effort parse (not recommended for production)
            event = stripe.Event.construct_from(stripe.util.json.loads(body), stripe.api_key)
        # Map Stripe event types to canonical events
        return {"type": event.type, "provider": "stripe", "payload": event.to_dict()}