"""Tests for StripeConnector implementation."""

import os
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import stripe

from payments_sdk.connectors.stripe_connector import StripeConnector, SENSITIVE_FIELDS
from payments_sdk.connectors.base import PaymentRequest, PaymentResponse


class TestStripeConnectorInit:
    """Tests for StripeConnector initialization."""

    def test_init_with_api_key_argument(self):
        """Test initialization with API key as argument."""
        connector = StripeConnector(api_key="sk_test_key")
        assert connector._api_key == "sk_test_key"

    def test_init_with_env_variable(self):
        """Test initialization with API key from environment."""
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_env_key"}):
            connector = StripeConnector()
            assert connector._api_key == "sk_test_env_key"

    def test_init_without_api_key_raises(self):
        """Test that initialization without API key raises ValueError."""
        with patch.dict(os.environ, {"STRIPE_API_KEY": ""}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                StripeConnector()
            assert "STRIPE_API_KEY" in str(exc_info.value)

    def test_argument_takes_precedence_over_env(self):
        """Test that argument API key takes precedence over environment."""
        with patch.dict(os.environ, {"STRIPE_API_KEY": "sk_test_env_key"}):
            connector = StripeConnector(api_key="sk_test_arg_key")
            assert connector._api_key == "sk_test_arg_key"


class TestStripeConnectorAuthorize:
    """Tests for StripeConnector.authorize method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_authorize_success(self, connector, valid_payment_request_data, mock_stripe_payment_intent):
        """Test successful authorization."""
        with patch("stripe.PaymentIntent.create", return_value=mock_stripe_payment_intent):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "authorized"
            assert response.id == "pi_1234567890abcdefghijklmno"
            assert response.provider_transaction_id == "pi_1234567890abcdefghijklmno"

    def test_authorize_with_capture_immediate(self, connector, valid_payment_request_data, mock_stripe_captured_intent):
        """Test authorization with capture_immediate intent."""
        valid_payment_request_data["intent"] = "capture_immediate"
        with patch("stripe.PaymentIntent.create", return_value=mock_stripe_captured_intent):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "captured"

    def test_authorize_requires_3ds(self, connector, valid_payment_request_data, mock_stripe_payment_intent_3ds):
        """Test authorization that requires 3DS."""
        with patch("stripe.PaymentIntent.create", return_value=mock_stripe_payment_intent_3ds):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "pending_mfa"
            assert response.mfa is not None
            assert response.mfa.type == "3ds"

    def test_authorize_card_error(self, connector, valid_payment_request_data):
        """Test authorization with card error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.CardError(
            message="Card declined",
            param="card",
            code="card_declined"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "card_error"

    def test_authorize_rate_limit_error(self, connector, valid_payment_request_data):
        """Test authorization with rate limit error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.RateLimitError(
            message="Too many requests"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "rate_limit"

    def test_authorize_invalid_request_error(self, connector, valid_payment_request_data):
        """Test authorization with invalid request error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.InvalidRequestError(
            message="Invalid request",
            param="amount"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"

    def test_authorize_authentication_error(self, connector, valid_payment_request_data):
        """Test authorization with authentication error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.AuthenticationError(
            message="Invalid API key"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "authentication_error"

    def test_authorize_connection_error(self, connector, valid_payment_request_data):
        """Test authorization with connection error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.APIConnectionError(
            message="Connection failed"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "connection_error"

    def test_authorize_api_error(self, connector, valid_payment_request_data):
        """Test authorization with generic API error."""
        with patch("stripe.PaymentIntent.create", side_effect=stripe.error.APIError(
            message="API error"
        )):
            request = PaymentRequest(**valid_payment_request_data)
            response = connector.authorize(request)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "api_error"

    def test_authorize_sets_correct_capture_method(self, connector, valid_payment_request_data):
        """Test that authorize sets correct capture method based on intent."""
        with patch("stripe.PaymentIntent.create") as mock_create:
            mock_pi = MagicMock()
            mock_pi.id = "pi_test"
            mock_pi.status = "requires_capture"
            mock_pi.to_dict.return_value = {"id": "pi_test", "status": "requires_capture"}
            mock_create.return_value = mock_pi

            request = PaymentRequest(**valid_payment_request_data)
            connector.authorize(request)

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["capture_method"] == "manual"

    def test_authorize_with_idempotency_key(self, connector, valid_payment_request_data):
        """Test that idempotency key is passed to Stripe."""
        with patch("stripe.PaymentIntent.create") as mock_create:
            mock_pi = MagicMock()
            mock_pi.id = "pi_test"
            mock_pi.status = "requires_capture"
            mock_pi.to_dict.return_value = {"id": "pi_test", "status": "requires_capture"}
            mock_create.return_value = mock_pi

            request = PaymentRequest(**valid_payment_request_data)
            connector.authorize(request)

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["idempotency_key"] == valid_payment_request_data["idempotency_key"]


class TestStripeConnectorCapture:
    """Tests for StripeConnector.capture method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_capture_success(self, connector, mock_stripe_captured_intent, valid_payment_id):
        """Test successful capture."""
        with patch("stripe.PaymentIntent.capture", return_value=mock_stripe_captured_intent):
            response = connector.capture(valid_payment_id, 1000)

            assert response.status == "captured"
            assert response.id == "pi_1234567890abcdefghijklmno"

    def test_capture_partial_amount(self, connector, valid_payment_id):
        """Test partial capture with different amount."""
        mock_pi = MagicMock()
        mock_pi.id = valid_payment_id
        mock_pi.status = "succeeded"
        mock_pi.to_dict.return_value = {"id": valid_payment_id, "status": "succeeded", "amount": 500}

        with patch("stripe.PaymentIntent.capture", return_value=mock_pi) as mock_capture:
            response = connector.capture(valid_payment_id, 500)

            mock_capture.assert_called_once_with(valid_payment_id, amount_to_capture=500)
            assert response.status == "captured"

    def test_capture_invalid_payment_intent(self, connector, valid_payment_id):
        """Test capture with invalid payment intent."""
        with patch("stripe.PaymentIntent.capture", side_effect=stripe.error.InvalidRequestError(
            message="Invalid payment intent",
            param="payment_intent"
        )):
            response = connector.capture(valid_payment_id, 1000)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"


class TestStripeConnectorRefund:
    """Tests for StripeConnector.refund method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_refund_success(self, connector, mock_stripe_refund, valid_payment_id):
        """Test successful refund."""
        with patch("stripe.Refund.create", return_value=mock_stripe_refund):
            response = connector.refund(valid_payment_id, 500)

            assert response.status == "refunded"
            assert response.id == "re_1234567890abcdefghijklmno"

    def test_refund_full_amount(self, connector, valid_payment_id):
        """Test full refund."""
        mock_refund = MagicMock()
        mock_refund.id = "re_test"
        mock_refund.to_dict.return_value = {"id": "re_test", "amount": 1000, "status": "succeeded"}

        with patch("stripe.Refund.create", return_value=mock_refund) as mock_create:
            response = connector.refund(valid_payment_id, 1000)

            mock_create.assert_called_once_with(payment_intent=valid_payment_id, amount=1000)
            assert response.status == "refunded"

    def test_refund_error(self, connector, valid_payment_id):
        """Test refund with error."""
        with patch("stripe.Refund.create", side_effect=stripe.error.InvalidRequestError(
            message="Cannot refund",
            param="payment_intent"
        )):
            response = connector.refund(valid_payment_id, 500)

            assert response.status == "failed"


class TestStripeConnectorVoid:
    """Tests for StripeConnector.void method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_void_success(self, connector, mock_stripe_canceled_intent, valid_payment_id):
        """Test successful void."""
        with patch("stripe.PaymentIntent.cancel", return_value=mock_stripe_canceled_intent):
            response = connector.void(valid_payment_id)

            assert response.status == "voided"
            assert response.id == "pi_1234567890abcdefghijklmno"

    def test_void_already_captured_error(self, connector, valid_payment_id):
        """Test void on already captured payment."""
        with patch("stripe.PaymentIntent.cancel", side_effect=stripe.error.InvalidRequestError(
            message="Cannot cancel",
            param="payment_intent"
        )):
            response = connector.void(valid_payment_id)

            assert response.status == "failed"


class TestStripeConnectorParseWebhook:
    """Tests for StripeConnector.parse_webhook method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_parse_webhook_success(self, connector):
        """Test successful webhook parsing."""
        mock_event = MagicMock()
        mock_event.type = "payment_intent.succeeded"
        mock_event.to_dict.return_value = {
            "type": "payment_intent.succeeded",
            "data": {"object": {"id": "pi_test"}}
        }

        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_test"}):
            with patch("stripe.Webhook.construct_event", return_value=mock_event):
                result = connector.parse_webhook(
                    {"stripe-signature": "sig_test"},
                    b'{"type": "test"}'
                )

                assert result["type"] == "payment_intent.succeeded"
                assert result["provider"] == "stripe"

    def test_parse_webhook_missing_secret(self, connector):
        """Test webhook parsing without webhook secret."""
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": ""}):
            with pytest.raises(ValueError) as exc_info:
                connector.parse_webhook(
                    {"stripe-signature": "sig_test"},
                    b'{"type": "test"}'
                )
            assert "STRIPE_WEBHOOK_SECRET" in str(exc_info.value)

    def test_parse_webhook_missing_signature(self, connector):
        """Test webhook parsing without signature header."""
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_test"}):
            with pytest.raises(ValueError) as exc_info:
                connector.parse_webhook({}, b'{"type": "test"}')
            assert "signature" in str(exc_info.value).lower()

    def test_parse_webhook_invalid_signature(self, connector):
        """Test webhook parsing with invalid signature."""
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_test"}):
            with patch("stripe.Webhook.construct_event", side_effect=stripe.error.SignatureVerificationError(
                message="Invalid signature",
                sig_header="invalid"
            )):
                with pytest.raises(ValueError) as exc_info:
                    connector.parse_webhook(
                        {"stripe-signature": "invalid_sig"},
                        b'{"type": "test"}'
                    )
                assert "signature" in str(exc_info.value).lower()


class TestStripeConnector3DS:
    """Tests for StripeConnector 3DS methods."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_get_3ds_challenge_success(self, connector, mock_stripe_payment_intent_3ds, valid_payment_id):
        """Test getting 3DS challenge data."""
        with patch("stripe.PaymentIntent.retrieve", return_value=mock_stripe_payment_intent_3ds):
            response = connector.get_3ds_challenge(valid_payment_id)

            assert response.payment_id == "pi_1234567890abcdefghijklmno"
            assert response.status == "pending_mfa"
            assert response.mfa is not None
            assert response.mfa.type == "3ds"

    def test_get_3ds_challenge_already_authorized(self, connector, mock_stripe_payment_intent, valid_payment_id):
        """Test getting 3DS challenge for already authorized payment."""
        with patch("stripe.PaymentIntent.retrieve", return_value=mock_stripe_payment_intent):
            response = connector.get_3ds_challenge(valid_payment_id)

            assert response.status == "authorized"
            assert response.mfa is None

    def test_get_3ds_challenge_error(self, connector, valid_payment_id):
        """Test getting 3DS challenge with error."""
        with patch("stripe.PaymentIntent.retrieve", side_effect=stripe.error.InvalidRequestError(
            message="Not found",
            param="payment_intent"
        )):
            response = connector.get_3ds_challenge(valid_payment_id)

            assert response.status == "failed"
            assert response.raw_provider_response["error_type"] == "invalid_request"

    def test_complete_3ds_success(self, connector, valid_payment_id):
        """Test completing 3DS authentication."""
        mock_pi_requiring_action = MagicMock()
        mock_pi_requiring_action.id = valid_payment_id
        mock_pi_requiring_action.status = "requires_action"
        mock_pi_requiring_action.to_dict.return_value = {"id": valid_payment_id, "status": "requires_action"}

        mock_pi_authorized = MagicMock()
        mock_pi_authorized.id = valid_payment_id
        mock_pi_authorized.status = "requires_capture"
        mock_pi_authorized.to_dict.return_value = {"id": valid_payment_id, "status": "requires_capture"}

        with patch("stripe.PaymentIntent.retrieve", return_value=mock_pi_requiring_action):
            with patch("stripe.PaymentIntent.confirm", return_value=mock_pi_authorized):
                response = connector.complete_3ds(valid_payment_id)

                assert response.status == "authorized"

    def test_complete_3ds_already_captured(self, connector, mock_stripe_captured_intent, valid_payment_id):
        """Test completing 3DS for already captured payment."""
        with patch("stripe.PaymentIntent.retrieve", return_value=mock_stripe_captured_intent):
            response = connector.complete_3ds(valid_payment_id)

            assert response.status == "captured"

    def test_complete_3ds_failed_authentication(self, connector, valid_payment_id):
        """Test completing 3DS when authentication failed."""
        mock_pi = MagicMock()
        mock_pi.id = valid_payment_id
        mock_pi.status = "requires_payment_method"
        mock_pi.to_dict.return_value = {"id": valid_payment_id, "status": "requires_payment_method"}

        with patch("stripe.PaymentIntent.retrieve", return_value=mock_pi):
            response = connector.complete_3ds(valid_payment_id)

            assert response.status == "failed"
            assert response.provider_response_code == "3ds_authentication_failed"

    def test_complete_3ds_voided(self, connector, mock_stripe_canceled_intent, valid_payment_id):
        """Test completing 3DS for canceled payment."""
        with patch("stripe.PaymentIntent.retrieve", return_value=mock_stripe_canceled_intent):
            response = connector.complete_3ds(valid_payment_id)

            assert response.status == "voided"


class TestStripeConnectorSanitization:
    """Tests for response sanitization."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_sanitize_removes_sensitive_fields(self, connector):
        """Test that sanitization removes sensitive fields."""
        raw_response = {
            "id": "pi_test",
            "client_secret": "pi_xxx_secret_xxx",
            "payment_method": "pm_xxx",
            "card": {"number": "4242..."},
            "status": "succeeded"
        }
        sanitized = connector._sanitize_response(raw_response)

        assert "id" in sanitized
        assert "status" in sanitized
        assert "client_secret" not in sanitized
        assert "payment_method" not in sanitized
        assert "card" not in sanitized

    def test_sanitize_nested_response(self, connector):
        """Test that sanitization works on nested objects."""
        raw_response = {
            "id": "pi_test",
            "charges": {
                "data": "safe_data",
                "payment_method_details": "sensitive"
            }
        }
        sanitized = connector._sanitize_response(raw_response)

        assert "id" in sanitized
        assert "charges" in sanitized
        assert "data" in sanitized["charges"]
        assert "payment_method_details" not in sanitized["charges"]

    def test_sanitize_empty_response(self, connector):
        """Test sanitization of empty response."""
        assert connector._sanitize_response({}) == {}
        assert connector._sanitize_response(None) == {}

    def test_all_sensitive_fields_are_filtered(self, connector):
        """Test that all defined sensitive fields are filtered."""
        raw_response = {field: "sensitive_value" for field in SENSITIVE_FIELDS}
        raw_response["safe_field"] = "safe_value"
        
        sanitized = connector._sanitize_response(raw_response)
        
        for field in SENSITIVE_FIELDS:
            assert field not in sanitized
        assert "safe_field" in sanitized


class TestStripeConnectorBuildMFAData:
    """Tests for _build_mfa_data method."""

    @pytest.fixture
    def connector(self, mock_stripe_api_key):
        """Create a StripeConnector instance."""
        return StripeConnector(api_key=mock_stripe_api_key)

    def test_build_mfa_data_redirect_to_url(self, connector):
        """Test building MFA data for redirect_to_url flow."""
        mock_pi = MagicMock()
        mock_pi.id = "pi_test123"
        mock_pi.to_dict.return_value = {
            "id": "pi_test123",
            "client_secret": "pi_test_secret",
            "next_action": {
                "type": "redirect_to_url",
                "redirect_to_url": {
                    "url": "https://hooks.stripe.com/3ds/redirect"
                }
            }
        }

        mfa = connector._build_mfa_data(mock_pi)

        assert mfa.type == "3ds"
        assert mfa.next_action_type == "redirect_to_url"
        assert mfa.challenge_data.acs_url == "https://hooks.stripe.com/3ds/redirect"

    def test_build_mfa_data_use_stripe_sdk(self, connector):
        """Test building MFA data for use_stripe_sdk flow."""
        mock_pi = MagicMock()
        mock_pi.id = "pi_test123"
        mock_pi.to_dict.return_value = {
            "id": "pi_test123",
            "client_secret": "pi_test_secret",
            "next_action": {
                "type": "use_stripe_sdk",
                "use_stripe_sdk": {}
            }
        }

        mfa = connector._build_mfa_data(mock_pi)

        assert mfa.type == "3ds"
        assert mfa.next_action_type == "use_stripe_sdk"
        assert mfa.redirect_url == "/payments/pi_test123/3ds"
