from .base import ConnectorBase, PaymentRequest, PaymentResponse

class TemplateConnector(ConnectorBase):
    """
    Example connector template. Copy this file, rename the class and package,
    and implement the methods using your PSP's SDK or HTTP API.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        # configure your PSP SDK/client here

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

    def parse_webhook(self, headers, body):
        # Validate and canonicalize
        return {"type": "payment.succeeded", "provider": "template", "payload": {}}