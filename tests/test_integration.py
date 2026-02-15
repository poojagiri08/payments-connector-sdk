"""Integration tests for payment flows."""

import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Set environment variables before importing app
os.environ.setdefault("STRIPE_API_KEY", "sk_test_dummy")
os.environ.setdefault("API_KEY", "test_api_key_12345")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test")

from payments_sdk.api import app
from payments_sdk.connectors.stripe_connector import StripeConnector
from payments_sdk.connectors.base import PaymentRequest, PaymentResponse, MFAData, ThreeDSChallengeResponse


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


class TestAuthorizeCaptureFLow:
    """Tests for authorize -> capture payment flow."""

    def test_authorize_then_capture_full_amount(self, client, auth_headers):
        """Test complete authorize -> capture flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Step 1: Authorize
        authorize_response = PaymentResponse(
            id=payment_id,
            status="authorized",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = authorize_response

            auth_result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_card_visa"},
                    "idempotency_key": "auth_key_123",
                    "intent": "authorize"
                },
                headers=auth_headers
            )

            assert auth_result.status_code == 200
            assert auth_result.json()["status"] == "authorized"

        # Step 2: Capture
        capture_response = PaymentResponse(
            id=payment_id,
            status="captured",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = capture_response

            capture_headers = {**auth_headers, "X-Idempotency-Key": "capture_key_123"}
            capture_result = client.post(
                f"/payments/{payment_id}/capture",
                json={"amount": 1000},
                headers=capture_headers
            )

            assert capture_result.status_code == 200
            assert capture_result.json()["status"] == "captured"

    def test_authorize_then_partial_capture(self, client, auth_headers):
        """Test authorize -> partial capture flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Step 1: Authorize for 1000
        authorize_response = PaymentResponse(
            id=payment_id,
            status="authorized",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = authorize_response

            auth_result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_card_visa"},
                    "idempotency_key": "auth_key_partial",
                    "intent": "authorize"
                },
                headers=auth_headers
            )

            assert auth_result.status_code == 200

        # Step 2: Partial capture for 500
        capture_response = PaymentResponse(
            id=payment_id,
            status="captured",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = capture_response

            capture_headers = {**auth_headers, "X-Idempotency-Key": "capture_partial_key"}
            capture_result = client.post(
                f"/payments/{payment_id}/capture",
                json={"amount": 500},
                headers=capture_headers
            )

            assert capture_result.status_code == 200
            assert capture_result.json()["status"] == "captured"


class TestAuthorizeVoidFlow:
    """Tests for authorize -> void payment flow."""

    def test_authorize_then_void(self, client, auth_headers):
        """Test complete authorize -> void flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Step 1: Authorize
        authorize_response = PaymentResponse(
            id=payment_id,
            status="authorized",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = authorize_response

            auth_result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_card_visa"},
                    "idempotency_key": "auth_void_key",
                    "intent": "authorize"
                },
                headers=auth_headers
            )

            assert auth_result.status_code == 200
            assert auth_result.json()["status"] == "authorized"

        # Step 2: Void
        void_response = PaymentResponse(
            id=payment_id,
            status="voided",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.void.return_value = void_response

            void_headers = {**auth_headers, "X-Idempotency-Key": "void_key_123"}
            void_result = client.post(
                f"/payments/{payment_id}/void",
                headers=void_headers
            )

            assert void_result.status_code == 200
            assert void_result.json()["status"] == "voided"


class TestAuthorizeCaptureRefundFlow:
    """Tests for authorize -> capture -> refund payment flow."""

    def test_full_flow_authorize_capture_refund(self, client, auth_headers):
        """Test complete authorize -> capture -> refund flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Step 1: Authorize
        authorize_response = PaymentResponse(
            id=payment_id,
            status="authorized",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = authorize_response

            auth_result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_card_visa"},
                    "idempotency_key": "auth_full_flow",
                    "intent": "authorize"
                },
                headers=auth_headers
            )

            assert auth_result.status_code == 200
            assert auth_result.json()["status"] == "authorized"

        # Step 2: Capture
        capture_response = PaymentResponse(
            id=payment_id,
            status="captured",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = capture_response

            capture_headers = {**auth_headers, "X-Idempotency-Key": "capture_full_flow"}
            capture_result = client.post(
                f"/payments/{payment_id}/capture",
                json={"amount": 1000},
                headers=capture_headers
            )

            assert capture_result.status_code == 200
            assert capture_result.json()["status"] == "captured"

        # Step 3: Refund
        refund_response = PaymentResponse(
            id="re_refund123",
            status="refunded",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.refund.return_value = refund_response

            refund_headers = {**auth_headers, "X-Idempotency-Key": "refund_full_flow"}
            refund_result = client.post(
                f"/payments/{payment_id}/refund",
                json={"amount": 1000},
                headers=refund_headers
            )

            assert refund_result.status_code == 200
            assert refund_result.json()["status"] == "refunded"

    def test_authorize_capture_partial_refund(self, client, auth_headers):
        """Test authorize -> capture -> partial refund flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Authorize
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = PaymentResponse(
                id=payment_id, status="authorized", provider_transaction_id=payment_id
            )
            client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_test"},
                    "idempotency_key": "auth_partial_refund"
                },
                headers=auth_headers
            )

        # Capture
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = PaymentResponse(
                id=payment_id, status="captured", provider_transaction_id=payment_id
            )
            client.post(
                f"/payments/{payment_id}/capture",
                json={"amount": 1000},
                headers={**auth_headers, "X-Idempotency-Key": "capture_partial_refund"}
            )

        # Partial refund
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.refund.return_value = PaymentResponse(
                id="re_partial", status="refunded", provider_transaction_id=payment_id
            )
            refund_result = client.post(
                f"/payments/{payment_id}/refund",
                json={"amount": 300},
                headers={**auth_headers, "X-Idempotency-Key": "partial_refund"}
            )

            assert refund_result.status_code == 200
            assert refund_result.json()["status"] == "refunded"


class TestAuthorize3DSCompleteFlow:
    """Tests for authorize -> 3DS -> complete flow."""

    def test_authorize_with_3ds_then_complete(self, client, auth_headers):
        """Test authorize requiring 3DS then completing it."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Step 1: Authorize (returns pending_mfa)
        mfa_data = MFAData(
            type="3ds",
            redirect_url=f"/payments/{payment_id}/3ds",
            next_action_type="use_stripe_sdk"
        )
        authorize_response = PaymentResponse(
            id=payment_id,
            status="pending_mfa",
            provider_transaction_id=payment_id,
            mfa=mfa_data
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = authorize_response

            auth_result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_card_3ds"},
                    "idempotency_key": "auth_3ds_key"
                },
                headers=auth_headers
            )

            assert auth_result.status_code == 200
            data = auth_result.json()
            assert data["status"] == "pending_mfa"
            assert data["mfa"]["type"] == "3ds"

        # Step 2: Get 3DS challenge
        challenge_response = ThreeDSChallengeResponse(
            payment_id=payment_id,
            status="pending_mfa",
            mfa=mfa_data
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.get_3ds_challenge.return_value = challenge_response

            get_headers = {k: v for k, v in auth_headers.items() if k != "X-Idempotency-Key"}
            challenge_result = client.get(
                f"/payments/{payment_id}/3ds",
                headers=get_headers
            )

            assert challenge_result.status_code == 200
            assert challenge_result.json()["status"] == "pending_mfa"

        # Step 3: Complete 3DS (after frontend handles challenge)
        complete_response = PaymentResponse(
            id=payment_id,
            status="authorized",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.complete_3ds.return_value = complete_response

            complete_headers = {**auth_headers, "X-Idempotency-Key": "complete_3ds_key"}
            complete_result = client.post(
                f"/payments/{payment_id}/3ds/complete",
                headers=complete_headers
            )

            assert complete_result.status_code == 200
            assert complete_result.json()["status"] == "authorized"

    def test_3ds_flow_then_capture(self, client, auth_headers):
        """Test full 3DS flow followed by capture."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Authorize with 3DS
        mfa_data = MFAData(type="3ds", redirect_url=f"/payments/{payment_id}/3ds")
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = PaymentResponse(
                id=payment_id, status="pending_mfa", provider_transaction_id=payment_id, mfa=mfa_data
            )
            client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_3ds"},
                    "idempotency_key": "auth_3ds_capture"
                },
                headers=auth_headers
            )

        # Complete 3DS
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.complete_3ds.return_value = PaymentResponse(
                id=payment_id, status="authorized", provider_transaction_id=payment_id
            )
            client.post(
                f"/payments/{payment_id}/3ds/complete",
                headers={**auth_headers, "X-Idempotency-Key": "complete_3ds_capture"}
            )

        # Capture
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.capture.return_value = PaymentResponse(
                id=payment_id, status="captured", provider_transaction_id=payment_id
            )
            capture_result = client.post(
                f"/payments/{payment_id}/capture",
                json={"amount": 1000},
                headers={**auth_headers, "X-Idempotency-Key": "capture_after_3ds"}
            )

            assert capture_result.status_code == 200
            assert capture_result.json()["status"] == "captured"


class TestConnectorIntegration:
    """Integration tests for StripeConnector using mocks."""

    def test_full_payment_lifecycle_with_connector(self, connector):
        """Test complete payment lifecycle through connector."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Mock for authorize
        mock_authorized = MagicMock()
        mock_authorized.id = payment_id
        mock_authorized.status = "requires_capture"
        mock_authorized.to_dict.return_value = {
            "id": payment_id,
            "status": "requires_capture",
            "amount": 1000
        }

        # Mock for capture
        mock_captured = MagicMock()
        mock_captured.id = payment_id
        mock_captured.status = "succeeded"
        mock_captured.to_dict.return_value = {
            "id": payment_id,
            "status": "succeeded",
            "amount": 1000
        }

        # Mock for refund
        mock_refund = MagicMock()
        mock_refund.id = "re_test"
        mock_refund.to_dict.return_value = {
            "id": "re_test",
            "amount": 1000,
            "status": "succeeded"
        }

        with patch("stripe.PaymentIntent.create", return_value=mock_authorized):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_key",
                payment_method={"token": "pm_test"}
            )
            auth_result = connector.authorize(request)
            assert auth_result.status == "authorized"

        with patch("stripe.PaymentIntent.capture", return_value=mock_captured):
            capture_result = connector.capture(payment_id, 1000)
            assert capture_result.status == "captured"

        with patch("stripe.Refund.create", return_value=mock_refund):
            refund_result = connector.refund(payment_id, 1000)
            assert refund_result.status == "refunded"

    def test_authorize_void_lifecycle_with_connector(self, connector):
        """Test authorize -> void lifecycle through connector."""
        payment_id = "pi_1234567890abcdefghijklmno"

        mock_authorized = MagicMock()
        mock_authorized.id = payment_id
        mock_authorized.status = "requires_capture"
        mock_authorized.to_dict.return_value = {"id": payment_id, "status": "requires_capture"}

        mock_canceled = MagicMock()
        mock_canceled.id = payment_id
        mock_canceled.status = "canceled"
        mock_canceled.to_dict.return_value = {"id": payment_id, "status": "canceled"}

        with patch("stripe.PaymentIntent.create", return_value=mock_authorized):
            request = PaymentRequest(
                amount=1000,
                currency="USD",
                idempotency_key="test_void",
                payment_method={"token": "pm_test"}
            )
            auth_result = connector.authorize(request)
            assert auth_result.status == "authorized"

        with patch("stripe.PaymentIntent.cancel", return_value=mock_canceled):
            void_result = connector.void(payment_id)
            assert void_result.status == "voided"


class TestCaptureImmediateFlow:
    """Tests for capture_immediate intent flow."""

    def test_capture_immediate_success(self, client, auth_headers):
        """Test capture_immediate intent creates captured payment."""
        payment_id = "pi_1234567890abcdefghijklmno"

        captured_response = PaymentResponse(
            id=payment_id,
            status="captured",
            provider_transaction_id=payment_id
        )

        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = captured_response

            result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_test"},
                    "idempotency_key": "capture_immediate_test",
                    "intent": "capture_immediate"
                },
                headers=auth_headers
            )

            assert result.status_code == 200
            assert result.json()["status"] == "captured"

    def test_capture_immediate_then_refund(self, client, auth_headers):
        """Test capture_immediate -> refund flow."""
        payment_id = "pi_1234567890abcdefghijklmno"

        # Capture immediate
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.authorize.return_value = PaymentResponse(
                id=payment_id, status="captured", provider_transaction_id=payment_id
            )
            result = client.post(
                "/payments",
                json={
                    "amount": 1000,
                    "currency": "USD",
                    "payment_method": {"token": "pm_test"},
                    "idempotency_key": "capture_imm_refund",
                    "intent": "capture_immediate"
                },
                headers=auth_headers
            )
            assert result.json()["status"] == "captured"

        # Refund
        with patch("payments_sdk.api.StripeConnector") as MockConnector:
            mock_instance = MockConnector.return_value
            mock_instance.refund.return_value = PaymentResponse(
                id="re_test", status="refunded", provider_transaction_id=payment_id
            )
            refund_result = client.post(
                f"/payments/{payment_id}/refund",
                json={"amount": 500},
                headers={**auth_headers, "X-Idempotency-Key": "refund_after_immediate"}
            )

            assert refund_result.status_code == 200
            assert refund_result.json()["status"] == "refunded"
