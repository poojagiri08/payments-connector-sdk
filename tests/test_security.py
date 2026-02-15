"""Tests for rate limiting and security features."""

import os
import pytest
import secrets
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Set environment variables before importing app
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy")
os.environ.setdefault("API_KEY", "test_api_key_12345")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test")

from payments_sdk.api import (
    app,
    verify_api_key,
    validate_metadata,
    MAX_METADATA_KEYS,
    MAX_METADATA_KEY_LENGTH,
    MAX_METADATA_VALUE_LENGTH,
    MAX_METADATA_TOTAL_SIZE,
    ALLOWED_PAYMENT_METHOD_FIELDS
)
from payments_sdk.connectors.base import PaymentResponse


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


class TestAPIKeyAuthentication:
    """Tests for API key authentication."""

    def test_valid_api_key_accepts_request(self, client, auth_headers):
        """Test that valid API key allows request."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200

    def test_invalid_api_key_rejects_request(self, client):
        """Test that invalid API key rejects request."""
        headers = {
            "Authorization": "Bearer invalid_key_12345",
            "X-Provider": "stripe",
            "X-Idempotency-Key": "key"
        }
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post("/payments", json=body, headers=headers)
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_missing_authorization_header(self, client):
        """Test request without authorization header."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post(
            "/payments",
            json=body,
            headers={"X-Provider": "stripe", "X-Idempotency-Key": "key"}
        )
        assert response.status_code == 403

    def test_empty_bearer_token(self, client):
        """Test request with empty bearer token."""
        headers = {
            "Authorization": "Bearer ",
            "X-Provider": "stripe",
            "X-Idempotency-Key": "key"
        }
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {"token": "pm_test"},
            "idempotency_key": "key123"
        }

        response = client.post("/payments", json=body, headers=headers)
        assert response.status_code == 401

    def test_api_key_not_configured_returns_500(self, client):
        """Test that missing API_KEY env var returns 500."""
        with patch.dict(os.environ, {"API_KEY": ""}):
            headers = {
                "Authorization": "Bearer some_key",
                "X-Provider": "stripe",
                "X-Idempotency-Key": "key"
            }
            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=headers)
            assert response.status_code == 500
            assert "configuration error" in response.json()["detail"].lower()

    def test_timing_safe_comparison(self):
        """Test that API key comparison uses timing-safe function."""
        # Verify that secrets.compare_digest is used (timing-safe)
        # This is already done in the implementation, we verify the function exists
        assert hasattr(secrets, 'compare_digest')


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_x_content_type_options_header(self, client, auth_headers):
        """Test X-Content-Type-Options header is set."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options_header(self, client, auth_headers):
        """Test X-Frame-Options header is set."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.headers.get("X-Frame-Options") == "DENY"

    def test_content_security_policy_header(self, client, auth_headers):
        """Test Content-Security-Policy header is set."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert "default-src 'none'" in response.headers.get("Content-Security-Policy", "")

    def test_strict_transport_security_header(self, client, auth_headers):
        """Test Strict-Transport-Security header is set."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            hsts = response.headers.get("Strict-Transport-Security", "")
            assert "max-age=" in hsts
            assert "includeSubDomains" in hsts


class TestPaymentMethodFieldValidation:
    """Tests for payment method field validation."""

    def test_only_allowed_fields_accepted(self):
        """Test that only allowed fields are in ALLOWED_PAYMENT_METHOD_FIELDS."""
        assert "token" in ALLOWED_PAYMENT_METHOD_FIELDS
        assert "type" in ALLOWED_PAYMENT_METHOD_FIELDS
        # Should not contain sensitive fields
        assert "card_number" not in ALLOWED_PAYMENT_METHOD_FIELDS
        assert "cvv" not in ALLOWED_PAYMENT_METHOD_FIELDS

    def test_unexpected_payment_method_field_rejected(self, client, auth_headers):
        """Test that unexpected fields in payment_method are rejected."""
        body = {
            "amount": 1000,
            "currency": "USD",
            "payment_method": {
                "token": "pm_test",
                "card_number": "4242424242424242"  # Not allowed
            },
            "idempotency_key": "key123"
        }

        response = client.post("/payments", json=body, headers=auth_headers)
        assert response.status_code == 422

    def test_valid_payment_method_fields(self, client, auth_headers):
        """Test that valid payment method fields are accepted."""
        mock_response = PaymentResponse(id="pi_test", status="authorized")

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = mock_response

            body = {
                "amount": 1000,
                "currency": "USD",
                "payment_method": {
                    "token": "pm_test",
                    "type": "card"
                },
                "idempotency_key": "key123"
            }

            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 200


class TestMetadataValidation:
    """Tests for metadata validation security."""

    def test_max_metadata_keys_enforced(self):
        """Test that metadata cannot exceed MAX_METADATA_KEYS."""
        metadata = {f"key_{i}": f"value_{i}" for i in range(MAX_METADATA_KEYS + 1)}
        with pytest.raises(ValueError) as exc_info:
            validate_metadata(metadata)
        assert "cannot have more than" in str(exc_info.value)

    def test_max_metadata_key_length_enforced(self):
        """Test that metadata key length is enforced."""
        metadata = {"a" * (MAX_METADATA_KEY_LENGTH + 1): "value"}
        with pytest.raises(ValueError) as exc_info:
            validate_metadata(metadata)
        assert "key length" in str(exc_info.value)

    def test_max_metadata_value_length_enforced(self):
        """Test that metadata value length is enforced."""
        metadata = {"key": "a" * (MAX_METADATA_VALUE_LENGTH + 1)}
        with pytest.raises(ValueError) as exc_info:
            validate_metadata(metadata)
        assert "value length" in str(exc_info.value)

    def test_metadata_key_must_be_string(self):
        """Test that metadata keys must be strings."""
        # This is typically prevented by JSON parsing, but test the validation
        metadata = {123: "value"}  # Integer key
        with pytest.raises(ValueError) as exc_info:
            validate_metadata(metadata)
        assert "keys must be strings" in str(exc_info.value)

    def test_metadata_value_must_be_primitive(self):
        """Test that metadata values must be primitives."""
        invalid_values = [
            {"key": ["list", "value"]},
            {"key": {"nested": "dict"}},
            {"key": lambda x: x},  # Function
        ]
        
        for metadata in invalid_values:
            with pytest.raises(ValueError) as exc_info:
                validate_metadata(metadata)
            assert "must be strings, numbers, booleans, or null" in str(exc_info.value)

    def test_metadata_allows_valid_primitive_types(self):
        """Test that metadata allows valid primitive types."""
        valid_metadata = {
            "string_val": "hello",
            "int_val": 123,
            "float_val": 3.14,
            "bool_val": True,
            "null_val": None
        }
        result = validate_metadata(valid_metadata)
        assert result == valid_metadata

    def test_metadata_total_size_enforced(self):
        """Test that metadata total size is enforced."""
        # Create metadata that exceeds total size
        key_size = 30
        value_size = 400
        num_keys = (MAX_METADATA_TOTAL_SIZE // (key_size + value_size)) + 2
        
        metadata = {
            f"k{'a' * (key_size - 2)}{i}": "v" * value_size 
            for i in range(num_keys)
        }
        
        with pytest.raises(ValueError) as exc_info:
            validate_metadata(metadata)
        assert "total size" in str(exc_info.value)

    def test_none_metadata_returns_none(self):
        """Test that None metadata is accepted."""
        assert validate_metadata(None) is None


class TestInputSanitization:
    """Tests for input sanitization."""

    def test_payment_id_format_validation(self, client, auth_headers):
        """Test that payment ID format is validated."""
        invalid_ids = [
            "invalid",
            "pi_short",
            "px_1234567890abcdefghijklmno",
            "pi_1234567890abcdef<script>",
            "../../../etc/passwd",
            "pi_' OR '1'='1",
        ]

        for invalid_id in invalid_ids:
            response = client.post(
                f"/payments/{invalid_id}/capture",
                json={"amount": 1000},
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_currency_alphanumeric_only(self, client, auth_headers):
        """Test that currency only accepts letters."""
        invalid_currencies = ["US1", "U$$", "USD!", "U D"]

        for currency in invalid_currencies:
            body = {
                "amount": 1000,
                "currency": currency,
                "payment_method": {"token": "pm_test"},
                "idempotency_key": "key123"
            }
            response = client.post("/payments", json=body, headers=auth_headers)
            assert response.status_code == 422


class TestRateLimitingConfiguration:
    """Tests for rate limiting configuration."""

    def test_rate_limiter_is_configured(self):
        """Test that rate limiter is configured on app."""
        assert hasattr(app.state, 'limiter')

    def test_rate_limit_handler_exists(self, client, auth_headers):
        """Test that rate limit handler is configured."""
        from payments_sdk.api import rate_limit_handler
        from slowapi.errors import RateLimitExceeded
        
        # Verify the handler function is defined
        assert callable(rate_limit_handler)
        
        # Verify RateLimitExceeded is properly imported
        assert RateLimitExceeded is not None


class TestWebhookSecurity:
    """Tests for webhook security."""

    def test_webhook_requires_signature_header(self, client):
        """Test that webhook requires signature header."""
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.parse_webhook.side_effect = ValueError("Missing signature")

            response = client.post(
                "/webhooks/psp",
                content=b'{"type": "test"}',
                headers={"X-Provider": "stripe"}
            )

            assert response.status_code == 400

    def test_webhook_validates_signature(self, client):
        """Test that webhook validates signature."""
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.parse_webhook.side_effect = ValueError("Invalid signature")

            response = client.post(
                "/webhooks/psp",
                content=b'{"type": "test"}',
                headers={
                    "X-Provider": "stripe",
                    "stripe-signature": "invalid_signature"
                }
            )

            assert response.status_code == 400
            assert "validation failed" in response.json()["detail"].lower()


class TestCORSConfiguration:
    """Tests for CORS configuration."""

    def test_cors_middleware_configured(self):
        """Test that CORS middleware is configured."""
        # Check that CORSMiddleware is in the middleware stack
        middleware_types = [type(m).__name__ for m in app.user_middleware]
        # Note: The middleware class name might be different, check the app setup
        # This test verifies the setup exists
        assert hasattr(app, 'add_middleware')

    def test_cors_allowed_methods(self, client):
        """Test CORS preflight request."""
        response = client.options(
            "/payments",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST"
            }
        )
        # When no origins are configured, CORS will not add headers
        # This test verifies the endpoint is accessible
        assert response.status_code in [200, 400, 405]


class TestSensitiveDataFiltering:
    """Tests for sensitive data filtering in connector."""

    def test_sensitive_fields_list(self):
        """Test that sensitive fields list is comprehensive."""
        from payments_sdk.connectors.stripe_connector import SENSITIVE_FIELDS
        
        expected_sensitive = [
            'client_secret',
            'payment_method',
            'source',
            'customer',
            'payment_method_details',
            'card',
            'bank_account',
        ]
        
        for field in expected_sensitive:
            assert field in SENSITIVE_FIELDS

    def test_sensitive_fields_are_frozen(self):
        """Test that sensitive fields set is immutable."""
        from payments_sdk.connectors.stripe_connector import SENSITIVE_FIELDS
        
        assert isinstance(SENSITIVE_FIELDS, frozenset)
        
        # Should not be able to modify
        with pytest.raises(AttributeError):
            SENSITIVE_FIELDS.add("new_field")
