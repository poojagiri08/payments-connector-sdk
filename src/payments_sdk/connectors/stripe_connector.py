import os
import logging
from typing import Dict, Any, Optional, List
import stripe
from .base import (
    ConnectorBase,
    PaymentRequest,
    PaymentResponse,
    LocalPaymentRequest,
    LocalPaymentMethodType,
    REGION_PAYMENT_METHODS,
    is_async_payment_method,
    is_redirect_payment_method,
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

# Mapping of our payment method types to Stripe payment method types
STRIPE_PAYMENT_METHOD_MAPPING: Dict[LocalPaymentMethodType, str] = {
    LocalPaymentMethodType.IDEAL: "ideal",
    LocalPaymentMethodType.SEPA_DEBIT: "sepa_debit",
    LocalPaymentMethodType.BANCONTACT: "bancontact",
    LocalPaymentMethodType.GIROPAY: "giropay",
    LocalPaymentMethodType.EPS: "eps",
    LocalPaymentMethodType.P24: "p24",
    LocalPaymentMethodType.SOFORT: "sofort",
    LocalPaymentMethodType.BOLETO: "boleto",
    LocalPaymentMethodType.OXXO: "oxxo",
    LocalPaymentMethodType.MULTIBANCO: "multibanco",
    LocalPaymentMethodType.ALIPAY: "alipay",
    LocalPaymentMethodType.WECHAT_PAY: "wechat_pay",
    LocalPaymentMethodType.BACS_DEBIT: "bacs_debit",
    LocalPaymentMethodType.BLIK: "blik",
    LocalPaymentMethodType.FPX: "fpx",
    LocalPaymentMethodType.GRABPAY: "grabpay",
    LocalPaymentMethodType.KLARNA: "klarna",
    LocalPaymentMethodType.AFTERPAY_CLEARPAY: "afterpay_clearpay",
    LocalPaymentMethodType.PIX: "pix",
    LocalPaymentMethodType.BANK_TRANSFER: "us_bank_account",
}

# Local payment methods supported by this connector
SUPPORTED_LOCAL_PAYMENT_METHODS: frozenset = frozenset([
    LocalPaymentMethodType.IDEAL,
    LocalPaymentMethodType.SEPA_DEBIT,
    LocalPaymentMethodType.BANCONTACT,
    LocalPaymentMethodType.GIROPAY,
    LocalPaymentMethodType.EPS,
    LocalPaymentMethodType.P24,
    LocalPaymentMethodType.SOFORT,
    LocalPaymentMethodType.BOLETO,
    LocalPaymentMethodType.OXXO,
    LocalPaymentMethodType.MULTIBANCO,
    LocalPaymentMethodType.ALIPAY,
    LocalPaymentMethodType.WECHAT_PAY,
    LocalPaymentMethodType.BACS_DEBIT,
    LocalPaymentMethodType.BLIK,
    LocalPaymentMethodType.FPX,
    LocalPaymentMethodType.GRABPAY,
    LocalPaymentMethodType.KLARNA,
    LocalPaymentMethodType.AFTERPAY_CLEARPAY,
    LocalPaymentMethodType.PIX,
    LocalPaymentMethodType.BANK_TRANSFER,
])


class StripeConnector(ConnectorBase):
    """
    Minimal Stripe connector using stripe-python. This example focuses on card payment
    flows using PaymentIntents. It expects that the merchant frontend obtains a
    payment method token / payment_method id from Stripe.js and passes it to the server.
    
    Also supports local payment methods including:
    - iDEAL (Netherlands)
    - SEPA Direct Debit (EU)
    - Bancontact (Belgium)
    - giropay (Germany)
    - EPS (Austria)
    - P24 (Poland)
    - SOFORT (EU)
    - Boleto (Brazil)
    - OXXO (Mexico)
    - Multibanco (Portugal)
    - Alipay (China)
    - WeChat Pay (China)
    - And more...
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

    def process_local_payment(self, request: LocalPaymentRequest) -> PaymentResponse:
        """
        Process a local payment method using Stripe's PaymentIntents API.
        
        For redirect-based methods (iDEAL, Bancontact, etc.):
        - Creates a PaymentIntent with the appropriate payment method type
        - Returns redirect_url for customer to complete payment
        
        For async methods (Boleto, OXXO, etc.):
        - Creates a PaymentIntent and returns payment instructions
        - Customer pays offline using the voucher/barcode
        """
        self._configure_stripe()
        
        pm_type = request.local_payment_method.type
        
        # Validate that we support this payment method
        if pm_type not in SUPPORTED_LOCAL_PAYMENT_METHODS:
            return PaymentResponse(
                id=None,
                status="failed",
                raw_provider_response={
                    "error_type": "unsupported_payment_method",
                    "message": f"Payment method '{pm_type.value}' is not supported by Stripe connector"
                }
            )
        
        try:
            stripe_pm_type = STRIPE_PAYMENT_METHOD_MAPPING.get(pm_type)
            if not stripe_pm_type:
                return PaymentResponse(
                    id=None,
                    status="failed",
                    raw_provider_response={
                        "error_type": "mapping_error",
                        "message": f"No Stripe mapping for payment method '{pm_type.value}'"
                    }
                )
            
            # Build payment method data based on the type
            payment_method_data = self._build_payment_method_data(request)
            
            # Create PaymentIntent with appropriate parameters
            create_kwargs = {
                "amount": request.amount,
                "currency": request.currency.lower(),
                "payment_method_types": [stripe_pm_type],
                "metadata": request.metadata or {},
            }
            
            if request.idempotency_key:
                create_kwargs["idempotency_key"] = request.idempotency_key
            
            # Add payment method data if available
            if payment_method_data:
                create_kwargs["payment_method_data"] = payment_method_data
                create_kwargs["confirm"] = True
            
            # Add return URL for redirect-based methods
            if is_redirect_payment_method(pm_type) and request.local_payment_method.return_url:
                create_kwargs["return_url"] = request.local_payment_method.return_url
            
            # Add statement descriptor if provided
            if request.statement_descriptor:
                create_kwargs["statement_descriptor"] = request.statement_descriptor
            
            pi = stripe.PaymentIntent.create(**create_kwargs)
            
            # Determine response status and extract relevant info
            return self._build_local_payment_response(pi, pm_type)
            
        except stripe.error.StripeError as e:
            return self._handle_stripe_error(e)

    def _build_payment_method_data(self, request: LocalPaymentRequest) -> Optional[Dict[str, Any]]:
        """Build Stripe payment_method_data based on the local payment method type."""
        pm = request.local_payment_method
        pm_type = pm.type
        stripe_type = STRIPE_PAYMENT_METHOD_MAPPING.get(pm_type)
        
        if not stripe_type:
            return None
        
        data: Dict[str, Any] = {"type": stripe_type}
        
        # iDEAL specific data
        if pm_type == LocalPaymentMethodType.IDEAL:
            if pm.bank_details and pm.bank_details.bank_code:
                data["ideal"] = {"bank": pm.bank_details.bank_code}
        
        # SEPA Direct Debit specific data
        elif pm_type == LocalPaymentMethodType.SEPA_DEBIT:
            if pm.bank_details and pm.bank_details.iban:
                data["sepa_debit"] = {"iban": pm.bank_details.iban}
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        # BACS Debit specific data
        elif pm_type == LocalPaymentMethodType.BACS_DEBIT:
            if pm.bank_details:
                data["bacs_debit"] = {
                    "sort_code": pm.bank_details.sort_code,
                    "account_number": pm.bank_details.account_number,
                }
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        # Boleto specific data
        elif pm_type == LocalPaymentMethodType.BOLETO:
            if pm.customer and pm.customer.tax_id:
                data["boleto"] = {"tax_id": pm.customer.tax_id}
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        # P24 specific data
        elif pm_type == LocalPaymentMethodType.P24:
            if pm.bank_details and pm.bank_details.bank_code:
                data["p24"] = {"bank": pm.bank_details.bank_code}
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        # FPX specific data
        elif pm_type == LocalPaymentMethodType.FPX:
            if pm.bank_details and pm.bank_details.bank_code:
                data["fpx"] = {"bank": pm.bank_details.bank_code}
        
        # Klarna specific data
        elif pm_type == LocalPaymentMethodType.KLARNA:
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        # Generic methods with billing details
        elif pm_type in [
            LocalPaymentMethodType.BANCONTACT,
            LocalPaymentMethodType.GIROPAY,
            LocalPaymentMethodType.EPS,
            LocalPaymentMethodType.SOFORT,
            LocalPaymentMethodType.OXXO,
            LocalPaymentMethodType.MULTIBANCO,
            LocalPaymentMethodType.PIX,
        ]:
            if pm.customer:
                data["billing_details"] = self._build_billing_details(pm.customer)
        
        return data

    def _build_billing_details(self, customer) -> Dict[str, Any]:
        """Build Stripe billing_details from CustomerDetails."""
        billing: Dict[str, Any] = {}
        
        if customer.name:
            billing["name"] = customer.name
        if customer.email:
            billing["email"] = customer.email
        if customer.phone:
            billing["phone"] = customer.phone
        
        # Build address if any address fields are present
        address: Dict[str, Any] = {}
        if customer.address_line1:
            address["line1"] = customer.address_line1
        if customer.address_line2:
            address["line2"] = customer.address_line2
        if customer.city:
            address["city"] = customer.city
        if customer.state:
            address["state"] = customer.state
        if customer.postal_code:
            address["postal_code"] = customer.postal_code
        if customer.country:
            address["country"] = customer.country
        
        if address:
            billing["address"] = address
        
        return billing

    def _build_local_payment_response(
        self,
        pi: Any,
        pm_type: LocalPaymentMethodType
    ) -> PaymentResponse:
        """Build PaymentResponse for local payment methods."""
        status_map = {
            "requires_action": "pending_redirect",
            "requires_confirmation": "pending_redirect",
            "processing": "pending_async",
            "requires_payment_method": "failed",
            "succeeded": "captured",
            "canceled": "voided",
        }
        
        # Determine status based on Stripe PI status and payment method type
        if pi.status == "requires_action" or pi.status == "requires_confirmation":
            if is_async_payment_method(pm_type):
                status = "pending_async"
            else:
                status = "pending_redirect"
        else:
            status = status_map.get(pi.status, "pending")
        
        # Extract redirect URL if available
        redirect_url = None
        if hasattr(pi, 'next_action') and pi.next_action:
            if hasattr(pi.next_action, 'redirect_to_url') and pi.next_action.redirect_to_url:
                redirect_url = pi.next_action.redirect_to_url.url
            elif hasattr(pi.next_action, 'type') and pi.next_action.type == 'redirect_to_url':
                redirect_url = getattr(pi.next_action, 'url', None)
        
        # Extract payment instructions for async methods
        payment_instructions = None
        if is_async_payment_method(pm_type) and hasattr(pi, 'next_action') and pi.next_action:
            instructions = {}
            next_action = pi.next_action
            
            # Boleto specific instructions
            if pm_type == LocalPaymentMethodType.BOLETO:
                if hasattr(next_action, 'boleto_display_details'):
                    details = next_action.boleto_display_details
                    if hasattr(details, 'number'):
                        instructions["barcode"] = details.number
                    if hasattr(details, 'hosted_voucher_url'):
                        instructions["voucher_url"] = details.hosted_voucher_url
                    if hasattr(details, 'expires_at'):
                        instructions["expires_at"] = details.expires_at
            
            # OXXO specific instructions
            elif pm_type == LocalPaymentMethodType.OXXO:
                if hasattr(next_action, 'oxxo_display_details'):
                    details = next_action.oxxo_display_details
                    if hasattr(details, 'number'):
                        instructions["voucher_number"] = details.number
                    if hasattr(details, 'hosted_voucher_url'):
                        instructions["voucher_url"] = details.hosted_voucher_url
                    if hasattr(details, 'expires_after'):
                        instructions["expires_at"] = details.expires_after
            
            # Multibanco specific instructions
            elif pm_type == LocalPaymentMethodType.MULTIBANCO:
                if hasattr(next_action, 'multibanco_display_details'):
                    details = next_action.multibanco_display_details
                    if hasattr(details, 'entity'):
                        instructions["entity"] = details.entity
                    if hasattr(details, 'reference'):
                        instructions["reference"] = details.reference
                    if hasattr(details, 'hosted_voucher_url'):
                        instructions["voucher_url"] = details.hosted_voucher_url
                    if hasattr(details, 'expires_at'):
                        instructions["expires_at"] = details.expires_at
            
            # PIX specific instructions
            elif pm_type == LocalPaymentMethodType.PIX:
                if hasattr(next_action, 'pix_display_qr_code'):
                    details = next_action.pix_display_qr_code
                    if hasattr(details, 'data'):
                        instructions["qr_code_data"] = details.data
                    if hasattr(details, 'image_url_svg'):
                        instructions["qr_code_url"] = details.image_url_svg
                    if hasattr(details, 'expires_at'):
                        instructions["expires_at"] = details.expires_at
            
            if instructions:
                payment_instructions = instructions
        
        return PaymentResponse(
            id=pi.id,
            status=status,
            provider_transaction_id=pi.id,
            raw_provider_response=self._sanitize_response(pi.to_dict()),
            redirect_url=redirect_url,
            payment_instructions=payment_instructions,
            expires_at=getattr(pi, 'expires_at', None),
        )

    def get_supported_local_payment_methods(self, region: Optional[str] = None) -> List[LocalPaymentMethodType]:
        """
        Get list of local payment methods supported by Stripe in a specific region.
        
        Args:
            region: ISO 3166-1 alpha-2 country code (optional)
            
        Returns:
            List of LocalPaymentMethodType values supported by both Stripe and the region
        """
        if region:
            region_methods = REGION_PAYMENT_METHODS.get(region.upper(), [])
            # Return intersection of Stripe supported methods and region methods
            return [m for m in region_methods if m in SUPPORTED_LOCAL_PAYMENT_METHODS]
        
        # Return all Stripe supported methods
        return list(SUPPORTED_LOCAL_PAYMENT_METHODS)

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
