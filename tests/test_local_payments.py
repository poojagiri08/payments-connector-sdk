"""
Tests for local payment methods functionality.
"""
import pytest
import sys
sys.path.insert(0, 'src')

from payments_sdk.connectors.base import (
    LocalPaymentMethod,
    LocalPaymentMethodType,
    LocalPaymentRequest,
    BankDetails,
    CustomerDetails,
    PaymentResponse,
    REGION_PAYMENT_METHODS,
    ASYNC_PAYMENT_METHODS,
    REDIRECT_PAYMENT_METHODS,
    validate_region_payment_method,
    get_supported_payment_methods,
    is_async_payment_method,
    is_redirect_payment_method,
)


class TestLocalPaymentMethodType:
    """Test LocalPaymentMethodType enum."""

    def test_all_payment_types_defined(self):
        """Verify all expected payment types are defined."""
        expected_types = [
            "bank_transfer", "boleto", "pix", "ideal", "sepa_debit",
            "bancontact", "giropay", "eps", "p24", "oxxo", "sofort",
            "multibanco", "alipay", "wechat_pay", "bacs_debit", "blik",
            "fpx", "grabpay", "klarna", "afterpay_clearpay"
        ]
        actual_types = [t.value for t in LocalPaymentMethodType]
        for expected in expected_types:
            assert expected in actual_types

    def test_enum_values_are_strings(self):
        """Verify enum values are lowercase strings."""
        for pm_type in LocalPaymentMethodType:
            assert isinstance(pm_type.value, str)
            assert pm_type.value.islower() or "_" in pm_type.value


class TestBankDetails:
    """Test BankDetails model."""

    def test_empty_bank_details(self):
        """Test creating empty bank details."""
        details = BankDetails()
        assert details.bank_code is None
        assert details.iban is None

    def test_full_bank_details(self):
        """Test creating full bank details."""
        details = BankDetails(
            bank_code="ING",
            bank_name="ING Bank",
            iban="DE89370400440532013000",
            bic="COBADEFFXXX",
            account_number="0532013000",
            routing_number="370400440",
            sort_code="108800"
        )
        assert details.bank_code == "ING"
        assert details.iban == "DE89370400440532013000"


class TestCustomerDetails:
    """Test CustomerDetails model."""

    def test_empty_customer_details(self):
        """Test creating empty customer details."""
        details = CustomerDetails()
        assert details.name is None
        assert details.email is None

    def test_full_customer_details(self):
        """Test creating full customer details."""
        details = CustomerDetails(
            name="John Doe",
            email="john@example.com",
            phone="+1234567890",
            tax_id="12345678909",
            address_line1="123 Main St",
            city="São Paulo",
            state="SP",
            postal_code="01304-000",
            country="BR"
        )
        assert details.name == "John Doe"
        assert details.tax_id == "12345678909"


class TestLocalPaymentMethod:
    """Test LocalPaymentMethod model and validation."""

    def test_ideal_requires_bank_code(self):
        """iDEAL requires bank_code."""
        with pytest.raises(ValueError, match="iDEAL requires bank_code"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.IDEAL,
                return_url="https://example.com/return"
            )

    def test_ideal_valid(self):
        """Valid iDEAL payment method."""
        pm = LocalPaymentMethod(
            type=LocalPaymentMethodType.IDEAL,
            bank_details=BankDetails(bank_code="ing"),
            return_url="https://example.com/return"
        )
        assert pm.type == LocalPaymentMethodType.IDEAL

    def test_sepa_requires_iban(self):
        """SEPA debit requires IBAN."""
        with pytest.raises(ValueError, match="SEPA debit requires bank_details with IBAN"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.SEPA_DEBIT,
                return_url="https://example.com/return"
            )

    def test_sepa_valid(self):
        """Valid SEPA payment method."""
        pm = LocalPaymentMethod(
            type=LocalPaymentMethodType.SEPA_DEBIT,
            bank_details=BankDetails(iban="DE89370400440532013000"),
            return_url="https://example.com/return"
        )
        assert pm.type == LocalPaymentMethodType.SEPA_DEBIT

    def test_boleto_requires_customer_info(self):
        """Boleto requires customer name and tax_id."""
        with pytest.raises(ValueError, match="Boleto requires customer name and tax_id"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.BOLETO,
                customer=CustomerDetails(name="John Doe")
            )

    def test_boleto_valid(self):
        """Valid Boleto payment method."""
        pm = LocalPaymentMethod(
            type=LocalPaymentMethodType.BOLETO,
            customer=CustomerDetails(
                name="João Silva",
                tax_id="12345678909"
            )
        )
        assert pm.type == LocalPaymentMethodType.BOLETO

    def test_pix_requires_email(self):
        """PIX requires customer email."""
        with pytest.raises(ValueError, match="PIX requires customer email"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.PIX,
                customer=CustomerDetails(name="Maria")
            )

    def test_pix_valid(self):
        """Valid PIX payment method."""
        pm = LocalPaymentMethod(
            type=LocalPaymentMethodType.PIX,
            customer=CustomerDetails(email="maria@example.com"),
            return_url="https://example.com/return"
        )
        assert pm.type == LocalPaymentMethodType.PIX

    def test_bacs_requires_sort_code_and_account(self):
        """BACS debit requires sort_code and account_number."""
        with pytest.raises(ValueError, match="BACS debit requires sort_code and account_number"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.BACS_DEBIT,
                bank_details=BankDetails(sort_code="108800"),
                return_url="https://example.com/return"
            )

    def test_bacs_valid(self):
        """Valid BACS payment method."""
        pm = LocalPaymentMethod(
            type=LocalPaymentMethodType.BACS_DEBIT,
            bank_details=BankDetails(
                sort_code="108800",
                account_number="00012345"
            ),
            return_url="https://example.com/return"
        )
        assert pm.type == LocalPaymentMethodType.BACS_DEBIT

    def test_redirect_method_requires_return_url(self):
        """Redirect-based methods require return_url."""
        with pytest.raises(ValueError, match="requires return_url for redirect flow"):
            LocalPaymentMethod(
                type=LocalPaymentMethodType.BANCONTACT
            )


class TestLocalPaymentRequest:
    """Test LocalPaymentRequest model."""

    def test_valid_request(self):
        """Test creating a valid local payment request."""
        request = LocalPaymentRequest(
            amount=2500,
            currency="EUR",
            idempotency_key="test-key-123",
            region="NL",
            local_payment_method=LocalPaymentMethod(
                type=LocalPaymentMethodType.IDEAL,
                bank_details=BankDetails(bank_code="ing"),
                return_url="https://example.com/return"
            )
        )
        assert request.amount == 2500
        assert request.currency == "EUR"
        assert request.region == "NL"

    def test_region_validation(self):
        """Test that region validates payment method support."""
        with pytest.raises(ValueError, match="not supported in region"):
            LocalPaymentRequest(
                amount=2500,
                currency="EUR",
                idempotency_key="test-key-123",
                region="US",  # iDEAL not supported in US
                local_payment_method=LocalPaymentMethod(
                    type=LocalPaymentMethodType.IDEAL,
                    bank_details=BankDetails(bank_code="ing"),
                    return_url="https://example.com/return"
                )
            )


class TestRegionValidation:
    """Test region-specific payment method validation."""

    def test_validate_ideal_in_netherlands(self):
        """iDEAL is valid in Netherlands."""
        assert validate_region_payment_method("NL", LocalPaymentMethodType.IDEAL)

    def test_validate_ideal_in_brazil_fails(self):
        """iDEAL is not valid in Brazil."""
        with pytest.raises(ValueError, match="not supported in region 'BR'"):
            validate_region_payment_method("BR", LocalPaymentMethodType.IDEAL)

    def test_validate_boleto_in_brazil(self):
        """Boleto is valid in Brazil."""
        assert validate_region_payment_method("BR", LocalPaymentMethodType.BOLETO)

    def test_validate_unknown_region(self):
        """Unknown region raises error."""
        with pytest.raises(ValueError, match="does not have local payment methods configured"):
            validate_region_payment_method("ZZ", LocalPaymentMethodType.IDEAL)

    def test_case_insensitive_region(self):
        """Region validation is case-insensitive."""
        assert validate_region_payment_method("nl", LocalPaymentMethodType.IDEAL)
        assert validate_region_payment_method("NL", LocalPaymentMethodType.IDEAL)


class TestGetSupportedPaymentMethods:
    """Test get_supported_payment_methods function."""

    def test_netherlands(self):
        """Test supported methods for Netherlands."""
        methods = get_supported_payment_methods("NL")
        assert LocalPaymentMethodType.IDEAL in methods
        assert LocalPaymentMethodType.SEPA_DEBIT in methods

    def test_brazil(self):
        """Test supported methods for Brazil."""
        methods = get_supported_payment_methods("BR")
        assert LocalPaymentMethodType.BOLETO in methods
        assert LocalPaymentMethodType.PIX in methods

    def test_germany(self):
        """Test supported methods for Germany."""
        methods = get_supported_payment_methods("DE")
        assert LocalPaymentMethodType.GIROPAY in methods
        assert LocalPaymentMethodType.SEPA_DEBIT in methods

    def test_unknown_region_returns_empty(self):
        """Unknown region returns empty list."""
        methods = get_supported_payment_methods("ZZ")
        assert methods == []


class TestPaymentMethodCategories:
    """Test async and redirect payment method categorization."""

    def test_async_methods(self):
        """Test that async methods are correctly identified."""
        assert is_async_payment_method(LocalPaymentMethodType.BOLETO)
        assert is_async_payment_method(LocalPaymentMethodType.OXXO)
        assert is_async_payment_method(LocalPaymentMethodType.MULTIBANCO)
        assert not is_async_payment_method(LocalPaymentMethodType.IDEAL)

    def test_redirect_methods(self):
        """Test that redirect methods are correctly identified."""
        assert is_redirect_payment_method(LocalPaymentMethodType.IDEAL)
        assert is_redirect_payment_method(LocalPaymentMethodType.BANCONTACT)
        assert is_redirect_payment_method(LocalPaymentMethodType.GIROPAY)
        assert is_redirect_payment_method(LocalPaymentMethodType.KLARNA)
        # Boleto is async, not redirect
        assert not is_redirect_payment_method(LocalPaymentMethodType.BOLETO)


class TestRegionPaymentMethodsMappings:
    """Test region payment method mappings."""

    def test_all_regions_have_methods(self):
        """All defined regions should have at least one payment method."""
        for region, methods in REGION_PAYMENT_METHODS.items():
            assert len(methods) > 0, f"Region {region} has no payment methods"

    def test_brazil_methods(self):
        """Brazil should have Boleto and PIX."""
        assert LocalPaymentMethodType.BOLETO in REGION_PAYMENT_METHODS["BR"]
        assert LocalPaymentMethodType.PIX in REGION_PAYMENT_METHODS["BR"]

    def test_eu_countries_have_sepa(self):
        """EU countries should support SEPA debit."""
        eu_countries = ["NL", "BE", "DE", "AT", "PT", "ES", "FR", "IT"]
        for country in eu_countries:
            assert LocalPaymentMethodType.SEPA_DEBIT in REGION_PAYMENT_METHODS[country], \
                f"{country} should support SEPA"

    def test_klarna_availability(self):
        """Klarna should be available in multiple regions."""
        klarna_regions = ["NL", "BE", "DE", "AT", "PL", "GB", "ES", "FR", "IT", "US"]
        for region in klarna_regions:
            assert LocalPaymentMethodType.KLARNA in REGION_PAYMENT_METHODS[region], \
                f"Klarna should be available in {region}"


class TestPaymentResponseFields:
    """Test PaymentResponse model has new fields for local payments."""

    def test_redirect_url_field(self):
        """PaymentResponse should have redirect_url field."""
        response = PaymentResponse(
            id="pi_123",
            status="pending_redirect",
            redirect_url="https://payment.provider.com/redirect"
        )
        assert response.redirect_url == "https://payment.provider.com/redirect"

    def test_payment_instructions_field(self):
        """PaymentResponse should have payment_instructions field."""
        response = PaymentResponse(
            id="pi_123",
            status="pending_async",
            payment_instructions={
                "barcode": "12345678901234567890",
                "voucher_url": "https://payment.provider.com/voucher"
            }
        )
        assert response.payment_instructions["barcode"] == "12345678901234567890"

    def test_expires_at_field(self):
        """PaymentResponse should have expires_at field."""
        response = PaymentResponse(
            id="pi_123",
            status="pending_async",
            expires_at="2026-02-20T00:00:00Z"
        )
        assert response.expires_at == "2026-02-20T00:00:00Z"

    def test_new_status_values(self):
        """PaymentResponse should support new status values."""
        for status in ["pending_redirect", "pending_async"]:
            response = PaymentResponse(id="pi_123", status=status)
            assert response.status == status
