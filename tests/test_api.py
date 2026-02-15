"""Tests for API endpoints."""

import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Set environment variables before importing app
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy")
os.environ.setdefault("API_KEY", "test_api_key_12345")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test")

from payments_sdk.api import app, validate_payment_id
from payments_sdk.connectors.base import PaymentResponse, ThreeDSChallengeResponse, MFAData


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


class TestPaymentIdValidation:
    """Tests for payment ID validation."""

    def test_valid_payment_id(self):
        """Test that valid payment ID passes validation."""
        valid_id = "pi_1234567890abcdefghijklmno"
        result = validate_payment_id(valid_id)
        assert result == valid_id

    def test_invalid_payment_id_format(self):
        """Test that invalid payment ID format raises HTTPException."""
        from fastapi import HTTPException
        
        invalid_ids = [
            "invalid_id",
            "pi_short",
            "px_1234567890abcdefghijklmno",
            "",
            "pi_!@#$%"
        ]
        
        for invalid_id in invalid_ids:
            with pytest.raises(HTTPException) as exc_info:
                validate_payment_id(invalid_id)
            assert exc_info.value.status_code == 400


class TestCreatePaymentEndpoint:
    """Tests for POST /payments endpoint."""

    def test_create_payment_success(self, client, auth_headers, valid_api_payment_body):
        """Test successful payment creation."""
        mock_response = PaymentResponse(
            id="pi_test123",
            status="authorized",
            provider_transaction_id="pi_test123"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            response = client.post(
                "/payments",
                json=valid_api_payment_body,
                headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "authorized"
            assert data["id"] == "pi_test123"

    def test_create_payment_missing_auth(self, client, valid_api_payment_body):
        """Test payment creation without authentication."""
        response = client.post(
            "/payments",
            json=valid_api_payment_body,
            headers={"X-Provider": "stripe", "X-Idempotency-Key": "key"}
        )

        assert response.status_code == 403

    def test_create_payment_invalid_auth(self, client, valid_api_payment_body):
        """Test payment creation with invalid API key."""
        headers = {
            "Authorization": "Bearer invalid_key",
            "X-Provider": "stripe",
            "X-Idempotency-Key": "key"
        }

        response = client.post(
            "/payments",
            json=valid_api_payment_body,
            headers=headers
        )

        assert response.status_code == 401

    def test_create_payment_invalid_amount(self, client, auth_headers):
        """Test payment creation with invalid amount."""
        body = {
            "amount": -100,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_zero_amount(self, client, auth_headers):
        """Test payment creation with zero amount."""
        body = {
            "amount": 0,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_exceeds_max_amount(self, client, auth_headers):
        """Test payment creation exceeding max amount."""
        body = {
            "amount": 100000000,  # Exceeds MAX_AMOUNT
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_invalid_currency(self, client, auth_headers):
        """Test payment creation with invalid currency."""
        body = {
            "amount": 1000,
            "currency": "US",  # Too short
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_missing_idempotency_key(self, client, auth_headers):
        """Test payment creation without idempotency key."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"}
        }
        
        # Remove idempotency key from headers too
        headers = {k: v for k, v in auth_headers.items() if k != "X-Idempotency-Key"}

        response = client.post(
            "/payments",
            json=body,
            headers=headers
        )

        assert response.status_code == 422

    def test_create_payment_invalid_intent(self, client, auth_headers):
        """Test payment creation with invalid intent."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123",
            "intent": "invalid_intent"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_invalid_payment_method_fields(self, client, auth_headers):
        """Test payment creation with unexpected payment method fields."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test", "unexpected_field": "value"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_create_payment_unsupported_provider(self, client, auth_headers, valid_api_payment_body):
        """Test payment creation with unsupported provider."""
        headers = {**auth_headers, "X-Provider": "unsupported_provider"}

        response = client.post(
            "/payments",
            json=valid_api_payment_body,
            headers=headers
        )

        assert response.status_code == 400
        assert "not supported" in response.json()["detail"].lower()


class TestCapturePaymentEndpoint:
    """Tests for POST /payments/{payment_id}/capture endpoint."""

    def test_capture_success(self, client, auth_headers):
        """Test successful capture."""
        mock_response = PaymentResponse(
            id="pi_1234567890abcdefghijklmno",
            status="captured",
            provider_transaction_id="pi_1234567890abcdefghijklmno"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = mock_response

            response = client.post(
                "/payments/pi_1234567890abcdefghijklmno/capture",
                json={"amount": 1000},
                headers=auth_headers
            )

            assert response.status_code == 200
            assert response.json()["status"] == "captured"

    def test_capture_invalid_payment_id(self, client, auth_headers):
        """Test capture with invalid payment ID."""
        response = client.post(
            "/payments/invalid_id/capture",
            json={"amount": 1000},
            headers=auth_headers
        )

        assert response.status_code == 400
        assert "Invalid payment ID" in response.json()["detail"]

    def test_capture_missing_amount(self, client, auth_headers):
        """Test capture without amount."""
        response = client.post(
            "/payments/pi_1234567890abcdefghijklmno/capture",
            json={},
            headers=auth_headers
        )

        assert response.status_code == 422

    def test_capture_missing_idempotency_key(self, client):
        """Test capture without idempotency key."""
        headers = {
            "Authorization": "Bearer test_api_key_12345",
            "X-Provider": "stripe"
        }

        response = client.post(
            "/payments/pi_1234567890abcdefghijklmno/capture",
            json={"amount": 1000},
            headers=headers
        )

        assert response.status_code == 422


class TestRefundPaymentEndpoint:
    """Tests for POST /payments/{payment_id}/refund endpoint."""

    def test_refund_success(self, client, auth_headers):
        """Test successful refund."""
        mock_response = PaymentResponse(
            id="re_test123",
            status="refunded",
            provider_transaction_id="pi_1234567890abcdefghijklmno"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.refund.return_value = mock_response

            response = client.post(
                "/payments/pi_1234567890abcdefghijklmno/refund",
                json={"amount": 500},
                headers=auth_headers
            )

            assert response.status_code == 200
            assert response.json()["status"] == "refunded"

    def test_refund_invalid_payment_id(self, client, auth_headers):
        """Test refund with invalid payment ID."""
        response = client.post(
            "/payments/invalid_id/refund",
            json={"amount": 500},
            headers=auth_headers
        )

        assert response.status_code == 400

    def test_refund_invalid_amount(self, client, auth_headers):
        """Test refund with invalid amount."""
        response = client.post(
            "/payments/pi_1234567890abcdefghijklmno/refund",
            json={"amount": 0},
            headers=auth_headers
        )

        assert response.status_code == 422


class TestVoidPaymentEndpoint:
    """Tests for POST /payments/{payment_id}/void endpoint."""

    def test_void_success(self, client, auth_headers):
        """Test successful void."""
        mock_response = PaymentResponse(
            id="pi_1234567890abcdefghijklmno",
            status="voided",
            provider_transaction_id="pi_1234567890abcdefghijklmno"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.void.return_value = mock_response

            response = client.post(
                "/payments/pi_1234567890abcdefghijklmno/void",
                headers=auth_headers
            )

            assert response.status_code == 200
            assert response.json()["status"] == "voided"

    def test_void_invalid_payment_id(self, client, auth_headers):
        """Test void with invalid payment ID."""
        response = client.post(
            "/payments/invalid_id/void",
            headers=auth_headers
        )

        assert response.status_code == 400


class TestGet3DSChallengeEndpoint:
    """Tests for GET /payments/{payment_id}/3ds endpoint."""

    def test_get_3ds_success(self, client, auth_headers):
        """Test successful 3DS challenge retrieval."""
        mock_response = ThreeDSChallengeResponse(
            payment_id="pi_1234567890abcdefghijklmno",
            status="pending_mfa",
            mfa=MFAData(type="3ds", redirect_url="/payments/pi_test/3ds")
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.get_3ds_challenge.return_value = mock_response

            # Remove idempotency key - not required for GET
            headers = {k: v for k, v in auth_headers.items() if k != "X-Idempotency-Key"}

            response = client.get(
                "/payments/pi_1234567890abcdefghijklmno/3ds",
                headers=headers
            )

            assert response.status_code == 200
            assert response.json()["status"] == "pending_mfa"

    def test_get_3ds_invalid_payment_id(self, client, auth_headers):
        """Test 3DS retrieval with invalid payment ID."""
        headers = {k: v for k, v in auth_headers.items() if k != "X-Idempotency-Key"}

        response = client.get(
            "/payments/invalid_id/3ds",
            headers=headers
        )

        assert response.status_code == 400


class TestComplete3DSEndpoint:
    """Tests for POST /payments/{payment_id}/3ds/complete endpoint."""

    def test_complete_3ds_success(self, client, auth_headers):
        """Test successful 3DS completion."""
        mock_response = PaymentResponse(
            id="pi_1234567890abcdefghijklmno",
            status="authorized",
            provider_transaction_id="pi_1234567890abcdefghijklmno"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.complete_3ds.return_value = mock_response

            response = client.post(
                "/payments/pi_1234567890abcdefghijklmno/3ds/complete",
                headers=auth_headers
            )

            assert response.status_code == 200
            assert response.json()["status"] == "authorized"

    def test_complete_3ds_with_auth_result(self, client, auth_headers):
        """Test 3DS completion with authentication result."""
        mock_response = PaymentResponse(
            id="pi_1234567890abcdefghijklmno",
            status="authorized"
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.complete_3ds.return_value = mock_response

            response = client.post(
                "/payments/pi_1234567890abcdefghijklmno/3ds/complete",
                json={"authentication_result": "success"},
                headers=auth_headers
            )

            assert response.status_code == 200

    def test_complete_3ds_invalid_payment_id(self, client, auth_headers):
        """Test 3DS completion with invalid payment ID."""
        response = client.post(
            "/payments/invalid_id/3ds/complete",
            headers=auth_headers
        )

        assert response.status_code == 400


class TestWebhookEndpoint:
    """Tests for POST /webhooks/psp endpoint."""

    def test_webhook_success(self, client):
        """Test successful webhook processing."""
        mock_event = {
            "type": "payment_intent.succeeded",
            "provider": "stripe",
            "payload": {"id": "pi_test"}
        }

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.parse_webhook.return_value = mock_event

            response = client.post(
                "/webhooks/psp",
                content=b'{"type": "payment_intent.succeeded"}',
                headers={
                    "stripe-signature": "t=123,v1=signature",
                    "X-Provider": "stripe"
                }
            )

            assert response.status_code == 200
            data = response.json()
            assert data["accepted"] is True
            assert data["event"]["type"] == "payment_intent.succeeded"

    def test_webhook_validation_failed(self, client):
        """Test webhook with validation failure."""
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.parse_webhook.side_effect = ValueError("Invalid signature")

            response = client.post(
                "/webhooks/psp",
                content=b'{"type": "test"}',
                headers={
                    "stripe-signature": "invalid",
                    "X-Provider": "stripe"
                }
            )

            assert response.status_code == 400
            assert "validation failed" in response.json()["detail"].lower()

    def test_webhook_unexpected_error(self, client):
        """Test webhook with unexpected error."""
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.parse_webhook.side_effect = Exception("Unexpected error")

            response = client.post(
                "/webhooks/psp",
                content=b'{"type": "test"}',
                headers={
                    "stripe-signature": "sig",
                    "X-Provider": "stripe"
                }
            )

            assert response.status_code == 400
            assert "failed" in response.json()["detail"].lower()


class TestMetadataValidation:
    """Tests for metadata validation in create payment."""

    def test_metadata_with_valid_data(self, client, auth_headers):
        """Test payment with valid metadata."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123",
                "metadata": {"order_id": "order_123", "customer": "cust_456"}
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_metadata_too_many_keys(self, client, auth_headers):
        """Test payment with too many metadata keys."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123",
            "metadata": {f"key_{i}": f"value_{i}" for i in range(51)}
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422

    def test_metadata_key_too_long(self, client, auth_headers):
        """Test payment with metadata key too long."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123",
            "metadata": {"a" * 41: "value"}
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422

    def test_metadata_value_too_long(self, client, auth_headers):
        """Test payment with metadata value too long."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123",
            "metadata": {"key": "a" * 501}
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422

    def test_metadata_invalid_value_type(self, client, auth_headers):
        """Test payment with invalid metadata value type."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123",
            "metadata": {"key": ["list", "not", "allowed"]}
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422


class TestSecurityHeaders:
    """Tests for security headers middleware."""

    def test_security_headers_present(self, client, auth_headers, valid_api_payment_body):
        """Test that security headers are added to responses."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            response = client.post(
                "/payments",
                json=valid_api_payment_body,
                headers=auth_headers
            )

            assert response.headers.get("X-Content-Type-Options") == "nosniff"
            assert response.headers.get("X-Frame-Options") == "DENY"
            assert "default-src 'none'" in response.headers.get("Content-Security-Policy", "")
            assert "max-age=" in response.headers.get("Strict-Transport-Security", "")
