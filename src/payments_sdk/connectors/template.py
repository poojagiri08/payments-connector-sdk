from typing import Dict, Any, List, Optional
from .base import (
    ConnectorBase,
    PaymentRequest,
    PaymentResponse,
    LocalPaymentRequest,
    LocalPaymentMethodType,
    is_async_payment_method,
    is_redirect_payment_method,
)


class TemplateConnector(ConnectorBase):
    """
    Example connector template. Copy this file, rename the class and package,
    and implement the methods using your PSP's SDK or HTTP API.
    
    This template includes all required methods for both standard card payments
    and local payment methods.
    """

    def __init__(self, api_key: str):
        self._api_key = api_key
        # configure your PSP SDK/client here

    def __repr__(self):
        return f"<TemplateConnector configured={bool(self._api_key)}>"

    def authorize(self, request: PaymentRequest) -> PaymentResponse:
        # Translate PaymentRequest -> PSP request
        # Call PSP SDK/API
        # Translate response -> PaymentResponse
        return PaymentResponse(
            id="tmpl_123",
            status="authorized",
            provider_transaction_id="provider_txn_123",
            raw_provider_response={"example": True},
        )

    def capture(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        return PaymentResponse(
            id="tmpl_capture_123", status="captured", provider_transaction_id=provider_transaction_id
        )

    def refund(self, provider_transaction_id: str, amount: int) -> PaymentResponse:
        return PaymentResponse(
            id="tmpl_refund_123", status="refunded", provider_transaction_id=provider_transaction_id
        )

    def void(self, provider_transaction_id: str) -> PaymentResponse:
        return PaymentResponse(id="tmpl_void_123", status="voided", provider_transaction_id=provider_transaction_id)

    def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        # Validate and canonicalize
        return {"type": "payment.succeeded", "provider": "template", "payload": {}}

    def process_local_payment(self, request: LocalPaymentRequest) -> PaymentResponse:
        """
        Process a local payment method.
        
        Example implementation:
        1. Validate the payment method is supported
        2. Build PSP-specific request
        3. Call PSP API
        4. Return appropriate response with redirect_url or payment_instructions
        """
        pm_type = request.local_payment_method.type
        
        # Example: Check if it's a redirect or async payment method
        if is_redirect_payment_method(pm_type):
            # For redirect methods, return a redirect URL
            return PaymentResponse(
                id="tmpl_local_123",
                status="pending_redirect",
                provider_transaction_id="provider_local_txn_123",
                redirect_url="https://payment.provider.com/redirect/123",
                raw_provider_response={"payment_method": pm_type.value},
            )
        elif is_async_payment_method(pm_type):
            # For async methods, return payment instructions
            return PaymentResponse(
                id="tmpl_local_123",
                status="pending_async",
                provider_transaction_id="provider_local_txn_123",
                payment_instructions={
                    "voucher_number": "1234567890",
                    "voucher_url": "https://payment.provider.com/voucher/123",
                },
                expires_at="2026-02-20T00:00:00Z",
                raw_provider_response={"payment_method": pm_type.value},
            )
        else:
            # Standard processing
            return PaymentResponse(
                id="tmpl_local_123",
                status="authorized",
                provider_transaction_id="provider_local_txn_123",
                raw_provider_response={"payment_method": pm_type.value},
            )

    def get_supported_local_payment_methods(
        self, region: Optional[str] = None
    ) -> List[LocalPaymentMethodType]:
        """
        Return list of local payment methods supported by this connector.
        
        Override this method to customize based on your PSP's capabilities.
        """
        # Example: Return all payment methods, or filter by region
        supported = [
            LocalPaymentMethodType.IDEAL,
            LocalPaymentMethodType.SEPA_DEBIT,
            LocalPaymentMethodType.BOLETO,
            # Add more as supported by your PSP
        ]
        return supported