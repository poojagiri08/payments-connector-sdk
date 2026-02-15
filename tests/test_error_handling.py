"""Tests for error handling and edge cases."""

import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import stripe

# Set environment variables before importing app
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy")
os.environ.setdefault("API_KEY", "test_api_key_12345")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test")

from payments_sdk.api import app
from payments_sdk.connectors.stripe_connector import StripeConnector
from payments_sdk.connectors.base import PaymentRequest, PaymentResponse


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Return authenticated headers."""
    return {
        "Authorization": "Bearer test_api_key_12345",
        "X-Provider": "stripe",
        "X-Idempotency-Key": "test-idempotency-key"
    }


@pytest.fixture
def connector():
    """Create a StripeConnector instance."""
    return StripeConnector(api_key="sk_test_mock")


class TestStripeErrorHandling:
    """Tests for Stripe API error handling."""

    def test_card_declined_error(self, connector):
        """Test handling of card declined error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.CardError(
            message="Your card was declined.",
            param="card",
            code="card_declined"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_decline",
                payment_method={"token": "pm_card_declined"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.id is None
            assert response.raw_provider_response["error_type"] == "card_error"

    def test_insufficient_funds_error(self, connector):
        """Test handling of insufficient funds error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.CardError(
            message="Your card has insufficient funds.",
            param="card",
            code="insufficient_funds"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_insufficient",
                payment_method={"token": "pm_card_insufficient"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "card_error"

    def test_expired_card_error(self, connector):
        """Test handling of expired card error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.CardError(
            message="Your card has expired.",
            param="card",
            code="expired_card"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_expired",
                payment_method={"token": "pm_card_expired"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"

    def test_rate_limit_exceeded(self, connector):
        """Test handling of rate limit error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.RateLimitError(
            message="Rate limit exceeded"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_rate_limit",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "rate_limit"

    def test_invalid_api_key(self, connector):
        """Test handling of invalid API key error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.AuthenticationError(
            message="Invalid API Key provided"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_auth",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "authentication_error"

    def test_network_error(self, connector):
        """Test handling of network connection error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.APIConnectionError(
            message="Network error communicating with Stripe"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_network",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "connection_error"

    def test_stripe_server_error(self, connector):
        """Test handling of Stripe server error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.APIError(
            message="An unexpected error occurred"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_server",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "api_error"

    def test_invalid_request_error(self, connector):
        """Test handling of invalid request error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.InvalidRequestError(
            message="Invalid parameter",
            param="amount"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_invalid",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"

    def test_unknown_stripe_error(self, connector):
        """Test handling of unknown Stripe error."""
        # Create a generic StripeError (base class)
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.StripeError(
            message="Unknown error"
        )):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_unknown",
                payment_method={"token": "pm_test"}
            )
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "payment_error"


class TestCaptureErrorHandling:
    """Tests for capture operation error handling."""

    def test_capture_nonexistent_payment(self, connector):
        """Test capture of non-existent payment."""
        with patch("stripe.PaymentIntent.capture", side_effect=stripe.error.InvalidRequestError(
            message="No such payment_intent: pi_invalid",
            param="payment_intent"
        )):
            response = connector.capture("pi_1234567890abcdefghijklmno", 1000)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"

    def test_capture_already_captured(self, connector):
        """Test capture of already captured payment."""
        with patch("stripe.PaymentIntent.capture", side_effect=stripe.error.InvalidRequestError(
            message="This PaymentIntent has already been captured",
            param="payment_intent"
        )):
            response = connector.capture("pi_1234567890abcdefghijklmno", 1000)

            assert response.status == "failed"

    def test_capture_amount_exceeds_authorized(self, connector):
        """Test capture with amount exceeding authorized amount."""
        with patch("stripe.PaymentIntent.capture", side_effect=stripe.error.InvalidRequestError(
            message="Amount to capture is greater than the amount authorized",
            param="amount_to_capture"
        )):
            response = connector.capture("pi_1234567890abcdefghijklmno", 10000)

            assert response.status == "failed"


class TestRefundErrorHandling:
    """Tests for refund operation error handling."""

    def test_refund_uncaptured_payment(self, connector):
        """Test refund of uncaptured payment."""
        with patch("stripe.Refund.create", side_effect=stripe.error.InvalidRequestError(
            message="This PaymentIntent has not been captured",
            param="payment_intent"
        )):
            response = connector.refund("pi_1234567890abcdefghijklmno", 500)

            assert response.status == "failed"

    def test_refund_exceeds_captured_amount(self, connector):
        """Test refund with amount exceeding captured amount."""
        with patch("stripe.Refund.create", side_effect=stripe.error.InvalidRequestError(
            message="Refund amount exceeds the remaining charge amount",
            param="amount"
        )):
            response = connector.refund("pi_1234567890abcdefghijklmno", 10000)

            assert response.status == "failed"

    def test_refund_already_refunded(self, connector):
        """Test refund of already fully refunded payment."""
        with patch("stripe.Refund.create", side_effect=stripe.error.InvalidRequestError(
            message="The PaymentIntent has already been fully refunded",
            param="payment_intent"
        )):
            response = connector.refund("pi_1234567890abcdefghijklmno", 500)

            assert response.status == "failed"


class TestVoidErrorHandling:
    """Tests for void operation error handling."""

    def test_void_already_captured(self, connector):
        """Test void of already captured payment."""
        with patch("stripe.PaymentIntent.cancel", side_effect=stripe.error.InvalidRequestError(
            message="Cannot cancel a captured PaymentIntent",
            param="payment_intent"
        )):
            response = connector.void("pi_1234567890abcdefghijklmno")

            assert response.status == "failed"

    def test_void_already_voided(self, connector):
        """Test void of already voided payment."""
        with patch("stripe.PaymentIntent.cancel", side_effect=stripe.error.InvalidRequestError(
            message="This PaymentIntent has already been canceled",
            param="payment_intent"
        )):
            response = connector.void("pi_1234567890abcdefghijklmno")

            assert response.status == "failed"


class TestAPIErrorResponses:
    """Tests for API error responses."""

    def test_missing_required_field(self, client, auth_headers):
        """Test error response for missing required field."""
        body = {
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
            # Missing amount
        }

        response = client.post("/payments", json=body, headers=auth_headers)

        assert response.status_code == 422
        assert "amount" in str(response.json()).lower()

    def test_invalid_json_body(self, client, auth_headers):
        """Test error response for invalid JSON body."""
        response = client.post(
            "/payments",
            content=b"not valid json",
            headers={**auth_headers, "Content-Type": "application/json"}
        )

        assert response.status_code == 422

    def test_empty_request_body(self, client, auth_headers):
        """Test error response for empty request body."""
        response = client.post(
            "/payments",
            json={},
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_wrong_content_type(self, client, auth_headers):
        """Test error response for wrong content type."""
        response = client.post(
            "/payments",
            content=b"amount=1000&currency=USD",
            headers={**auth_headers, "Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code == 422

    def test_null_values_for_required_fields(self, client, auth_headers):
        """Test error response for null required fields."""
        body = {
            "amount": None,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post("/payments", json=body, headers=auth_headers)

        assert response.status_code == 422


class TestEdgeCases:
    """Tests for edge cases."""

    def test_minimum_valid_amount(self, client, auth_headers):
        """Test with minimum valid amount (1)."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_maximum_valid_amount(self, client, auth_headers):
        """Test with maximum valid amount."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 99999999,  # MAX_AMOUNT
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_currency_case_insensitivity(self, client, auth_headers):
        """Test that currency is case insensitive."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            for currency in ["usd", "USD", "Usd"]:
                body = {
                    "amount": 1000,
                    "currency": currency,
                    "payment_method": {"token": "pm_test"},
                    "idempotency_key": f"key_{currency}"
                }

                response = client.post("/payments", json=body, headers=auth_headers)
                assert response.status_code == 200

    def test_long_idempotency_key(self, client, auth_headers):
        """Test with maximum length idempotency key."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "k" * 255  # Max length
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_idempotency_key_too_long(self, client, auth_headers):
        """Test with idempotency key exceeding max length."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "k" * 256  # Exceeds max length
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422

    def test_empty_metadata(self, client, auth_headers):
        """Test with empty metadata."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123",
                "metadata": {}
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_payment_id_boundary_cases(self, client, auth_headers):
        """Test payment ID validation boundary cases."""
        from payments_sdk.api import validate_payment_id, PAYMENT_ID_PATTERN
        from fastapi import HTTPException

        # Valid ID (exactly 24 chars after pi_)
        valid_id = "pi_" + "a" * 24
        assert validate_payment_id(valid_id) == valid_id

        # Valid ID (longer than 24 chars)
        valid_id_long = "pi_" + "a" * 30
        assert validate_payment_id(valid_id_long) == valid_id_long

        # Invalid ID (less than 24 chars after pi_)
        invalid_id = "pi_" + "a" * 23
        with pytest.raises(HTTPException) as exc_info:
            validate_payment_id(invalid_id)
        assert exc_info.value.status_code == 400

    def test_special_characters_in_metadata_values(self, client, auth_headers):
        """Test metadata with special characters."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123",
                "metadata": {
                    "special": "value with spaces",
                    "unicode": "日本語テスト",
                    "symbols": "test@example.com"
                }
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200


class TestWebhookErrorHandling:
    """Tests for webhook error handling."""

    def test_webhook_signature_verification_failure(self, connector):
        """Test webhook with invalid signature."""
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_test"}):
            with patch("stripe.Webhook.construct_event", side_effect=stripe.error.SignatureVerificationError(
                message="Invalid signature",
                sig_header="invalid_sig"
            )):
                with pytest.raises(ValueError) as exc_info:
                    connector.parse_webhook(
                        {"stripe-signature": "invalid"},
                        b'{"type": "test"}'
                    )
                assert "signature" in str(exc_info.value).lower()

    def test_webhook_malformed_payload(self, connector):
        """Test webhook with malformed payload."""
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_test"}):
            with patch("stripe.Webhook.construct_event", side_effect=ValueError("Invalid JSON")):
                with pytest.raises(ValueError):
                    connector.parse_webhook(
                        {"stripe-signature": "valid_sig"},
                        b'not valid json'
                    )


class Test3DSErrorHandling:
    """Tests for 3DS error handling."""

    def test_get_3ds_challenge_not_found(self, connector):
        """Test getting 3DS challenge for non-existent payment."""
        with patch("stripe.PaymentIntent.retrieve", side_effect=stripe.error.InvalidRequestError(
            message="No such payment_intent",
            param="payment_intent"
        )):
            response = connector.get_3ds_challenge("pi_1234567890abcdefghijklmno")

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"

    def test_complete_3ds_stripe_error(self, connector):
        """Test completing 3DS with Stripe error."""
        with patch("stripe.PaymentIntent.retrieve", side_effect=stripe.error.APIError(
            message="Internal server error"
        )):
            response = connector.complete_3ds("pi_1234567890abcdefghijklmno")

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "api_error"

    def test_complete_3ds_confirm_failure(self, connector):
        """Test completing 3DS when confirm fails."""
        mock_pi = MagicMock()
        mock_pi.id = "pi_1234567890abcdefghijklmno"
        mock_pi.status = "requires_action"

        with patch("stripe.PaymentIntent.retrieve", return_value=mock_pi):
            with patch("stripe.PaymentIntent.confirm", side_effect=stripe.error.CardError(
                message="3DS authentication failed",
                param="card",
                code="authentication_required"
            )):
                response = connector.complete_3ds("pi_1234567890abcdefghijklmno")

                assert response.status == "failed"
                assert response.raw_provider_response["error_type"] == "card_error"
