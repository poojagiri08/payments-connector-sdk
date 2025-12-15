"""
Simple merchant usage example (server-side). The merchant obtains a payment_method
token using Stripe.js on the frontend, then POSTs to their server which calls this SDK.
"""
import os
from payments_sdk.connectors.stripe_connector import StripeConnector
from payments_sdk.connectors.base import PaymentRequest

def run():
    os.environ.setdefault("STRIPE_API_KEY", "")  # set your test key in env
    connector = StripeConnector()
    # Example PaymentRequest where payment_method.token is a Stripe PaymentMethod id
    req = PaymentRequest(
        amount=1000,
        currency="USD",
        payment_method={"type": "card", "token": "pm_card_visa"},
        idempotency_key="idem-123",
        intent="authorize",
    )
    resp = connector.authorize(req)
    print("Response:", resp.json())

if __name__ == "__main__":
    run()