import os
import logging
from typing import Dict, Any, Optional
import stripe
from .base import (
    ConnectorBase, 
    PaymentRequest, 
    PaymentResponse, 
    MFAData, 
    ThreeDSChallengeData,
    ThreeDSChallengeResponse
)

logger = logging.getLogger(__name__)

SENSITIVE_FIELDS = frozenset([
    'client_secret',
    'payment_method',
    'source',
    'customer',
    'payment_method_details',
    'card',
    'bank_account',
    'ach_credit_transfer',
    'ach_debit',
])


class StripeConnector(ConnectorBase):
    """
    Minimal Stripe connector using stripe-python. This example focuses on card payment
    flows using PaymentIntents. It expects that the merchant frontend obtains a
    payment method token / payment_method id from Stripe.js and passes it to the server.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.getenv("STRIPE_API_KEY")
        if not self._api_key:
            raise ValueError("STRIPE_API_KEY must be provided either as argument or environment variable")

    def _configure_stripe(self) -> None:
        stripe.api_key = self._api_key

    def _sanitize_response(self, raw_response: Dict[str, Any]) -> Dict[str, Any]:
        if not raw_response:
            return {}
        sanitized = {}
        for key, value in raw_response.items():
            if key in SENSITIVE_FIELDS:
                continue
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_response(value)
            else:
                sanitized[key] = value
        return sanitized

    def _handle_stripe_error(self, e: stripe.error.StripeError) -> PaymentResponse:
        logger.error(f"Stripe error occurred: {type(e).__name__}")
        error_mapping = {
            stripe.error.CardError: "card_error",
            stripe.error.RateLimitError: "rate_limit",
            stripe.error.InvalidRequestError: "invalid_request",
            stripe.error.AuthenticationError: "authentication_error",
            stripe.error.APIConnectionError: "connection_error",
            stripe.error.APIError: "api_error",
        }
        error_type = error_mapping.get(type(e), "payment_error")
        return PaymentResponse(
            id=None,
            status="failed",
            raw_provider_response={"error_type": error_type, "message": "Payment processing failed"}
        )

    def authorize(self, request: PaymentRequest) -> PaymentResponse:
        self._configure_stripe()
        try:
            capture_method = "manual" if request.intent == "authorize" else "automatic"
            create_kwargs = {
                "amount": request.amount,
                "currency": request.currency.lower(),
                "payment_method": request.payment_method.get("token"),
                "confirmation_method": "manual",
                "confirm": True,
                "capture_method": capture_method,
                "metadata": request.metadata or {},
            }
            if request.idempotency_key:
                create_kwargs["idempotency_key"] = request.idempotency_key
            pi = stripe.PaymentIntent.create(**create_kwargs)
            status_map = {
                "requires_capture": "authorized",
                "requires_action": "pending_mfa",
                "succeeded": "captured",
                "requires_payment_method": "failed",
            }
            status = status_map.get(pi.status, "pending")
            mfa = None
            if pi.status == "requires_action":
                mfa = self._build_mfa_data(pi)
            return PaymentResponse(
                id=pi.id,
                status=status,
                provider_transaction_id=pi.id,
                raw_provider_response=self._sanitize_response(pi.to_dict()),
                mfa=mfa,
            )
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)

    def _build_mfa_data(self, payment_intent) -> MFAData:
        """Build MFA data structure from Stripe PaymentIntent requiring action"""
        pi_dict = payment_intent.to_dict() if hasattr(payment_intent, 'to_dict') else payment_intent
        next_action = pi_dict.get("next_action", {})
        next_action_type = next_action.get("type") if next_action else None
        
        challenge_data = ThreeDSChallengeData(
            client_secret=pi_dict.get("client_secret"),
            transaction_id=payment_intent.id,
            version="2.0"  # Default to 3DS2
        )
        
        # Handle different next_action types from Stripe
        if next_action_type == "redirect_to_url":
            redirect_info = next_action.get("redirect_to_url", {})
            challenge_data.acs_url = redirect_info.get("url")
        elif next_action_type == "use_stripe_sdk":
            # For use_stripe_sdk, the client_secret is used by Stripe.js
            pass
        
        return MFAData(
            type="3ds",
            redirect_url=f"/payments/{payment_intent.id}/3ds",
            challenge_data=challenge_data,
            next_action_type=next_action_type
        )

    def capture(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        self._configure_stripe()
        try:
            captured = stripe.PaymentIntent.capture(provider_transaction_id, amount_to_capture=amount)
            return PaymentResponse(
                id=captured.id,
                status="captured",
                provider_transaction_id=captured.id,
                raw_provider_response=self._sanitize_response(captured.to_dict())
            )
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)

    def refund(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        self._configure_stripe()
        try:
            r = stripe.Refund.create(payment_intent=provider_transaction_id, amount=amount)
            return PaymentResponse(
                id=r.id,
                status="refunded",
                provider_transaction_id=provider_transaction_id,
                raw_provider_response=self._sanitize_response(r.to_dict())
            )
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)

    def void(self, provider_transaction_id: str) -> PaymentResponse:
        self._configure_stripe()
        try:
            pi = stripe.PaymentIntent.cancel(provider_transaction_id)
            return PaymentResponse(
                id=pi.id,
                status="voided",
                provider_transaction_id=pi.id,
                raw_provider_response=self._sanitize_response(pi.to_dict())
            )
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)

    def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        self._configure_stripe()
        webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        if not webhook_secret:
            raise ValueError("STRIPE_WEBHOOK_SECRET must be configured for webhook verification")
        sig_header = headers.get("stripe-signature", "")
        if not sig_header:
            raise ValueError("Missing stripe-signature header")
        try:
            event = stripe.Webhook.construct_event(payload=body, sig_header=sig_header, secret=webhook_secret)
        except stripe.error.SignatureVerificationError as e:
            logger.warning("Invalid webhook signature received")
            raise ValueError("Invalid webhook signature") from e
        except Exception as e:
            logger.error("Webhook parsing error")
            raise ValueError("Failed to parse webhook") from e
        return {"type": event.type, "provider": "stripe", "payload": self._sanitize_response(event.to_dict())}

    def get_3ds_challenge(self, payment_id: str) -> ThreeDSChallengeResponse:
        """
        Retrieve 3DS challenge data for a payment that requires MFA.
        Fetches the PaymentIntent from Stripe and returns challenge information.
        """
        self._configure_stripe()
        try:
            pi = stripe.PaymentIntent.retrieve(payment_id)
            
            # Map Stripe status to our canonical status
            status_map = {
                "requires_action": "pending_mfa",
                "requires_capture": "authorized",
                "succeeded": "captured",
                "requires_payment_method": "failed",
                "canceled": "voided",
            }
            status = status_map.get(pi.status, pi.status)
            
            mfa = None
            if pi.status == "requires_action":
                mfa = self._build_mfa_data(pi)
            
            return ThreeDSChallengeResponse(
                payment_id=pi.id,
                status=status,
                mfa=mfa,
                raw_provider_response=self._sanitize_response(pi.to_dict())
            )
        except stripe.error.StripeError as e:
            logger.error(f"Failed to retrieve 3DS challenge for {payment_id}: {type(e).__name__}")
            error_mapping = {
                stripe.error.InvalidRequestError: "invalid_request",
                stripe.error.AuthenticationError: "authentication_error",
                stripe.error.APIConnectionError: "connection_error",
                stripe.error.APIError: "api_error",
            }
            error_type = error_mapping.get(type(e), "payment_error")
            return ThreeDSChallengeResponse(
                payment_id=payment_id,
                status="failed",
                mfa=None,
                raw_provider_response={"error_type": error_type, "message": "Failed to retrieve 3DS challenge"}
            )

    def complete_3ds(self, payment_id: str, authentication_result: Optional[str] = None) -> PaymentResponse:
        """
        Complete 3DS authentication for a payment.
        This confirms the PaymentIntent after the 3DS challenge is completed by the frontend.
        Transitions payment from pending_mfa to authorized (or captured if capture_method is automatic).
        """
        self._configure_stripe()
        try:
            # First retrieve the PaymentIntent to check its current status
            pi = stripe.PaymentIntent.retrieve(payment_id)
            
            if pi.status == "requires_action":
                # Confirm the PaymentIntent to complete the 3DS flow
                # The frontend should have already handled the 3DS challenge
                pi = stripe.PaymentIntent.confirm(payment_id)
            elif pi.status in ["requires_capture", "succeeded"]:
                # Already completed - return current status
                logger.info(f"PaymentIntent {payment_id} already completed with status {pi.status}")
            elif pi.status == "requires_payment_method":
                # 3DS authentication failed - payment method needs to be updated
                return PaymentResponse(
                    id=pi.id,
                    status="failed",
                    provider_transaction_id=pi.id,
                    provider_response_code="3ds_authentication_failed",
                    raw_provider_response=self._sanitize_response(pi.to_dict())
                )
            elif pi.status == "canceled":
                return PaymentResponse(
                    id=pi.id,
                    status="voided",
                    provider_transaction_id=pi.id,
                    raw_provider_response=self._sanitize_response(pi.to_dict())
                )
            
            # Map final status
            status_map = {
                "requires_capture": "authorized",
                "requires_action": "pending_mfa",
                "succeeded": "captured",
                "requires_payment_method": "failed",
                "canceled": "voided",
            }
            status = status_map.get(pi.status, "pending")
            
            # Check if still requires action after confirm attempt
            mfa = None
            if pi.status == "requires_action":
                mfa = self._build_mfa_data(pi)
            
            return PaymentResponse(
                id=pi.id,
                status=status,
                provider_transaction_id=pi.id,
                raw_provider_response=self._sanitize_response(pi.to_dict()),
                mfa=mfa
            )
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)