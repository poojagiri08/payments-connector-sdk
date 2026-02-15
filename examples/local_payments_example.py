"""
Example configurations for local payment methods.

This module demonstrates how to configure and use various local payment methods
supported by the payments-connector-sdk. Each example shows the required fields
and typical usage patterns for different regions.
"""
import os
from payments_sdk.connectors import (
    StripeConnector,
    LocalPaymentRequest,
    LocalPaymentMethod,
    LocalPaymentMethodType,
    BankDetails,
    CustomerDetails,
    get_supported_payment_methods,
    validate_region_payment_method,
)


# =============================================================================
# iDEAL (Netherlands)
# =============================================================================
def create_ideal_payment():
    """
    iDEAL is the most popular online payment method in the Netherlands.
    Customers are redirected to their bank to authenticate the payment.
    
    Required fields:
    - bank_code: The customer's bank (e.g., 'abn_amro', 'ing', 'rabobank')
    - return_url: URL to redirect after payment completion
    """
    os.environ.setdefault("STRIPE_API_KEY", "")  # Set your test key
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=2500,  # €25.00 in cents
        currency="EUR",
        idempotency_key="ideal-payment-001",
        region="NL",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.IDEAL,
            bank_details=BankDetails(bank_code="ing"),
            return_url="https://example.com/payment/complete",
        ),
        metadata={"order_id": "order-12345"},
    )
    
    response = connector.process_local_payment(request)
    print(f"iDEAL Payment Response: {response.model_dump_json(indent=2)}")
    # Customer should be redirected to response.redirect_url
    return response


# =============================================================================
# SEPA Direct Debit (EU)
# =============================================================================
def create_sepa_debit_payment():
    """
    SEPA Direct Debit allows merchants to collect payments directly from
    customer bank accounts in the SEPA zone (EU countries).
    
    Required fields:
    - IBAN: Customer's International Bank Account Number
    - Customer name: Required for mandate creation
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=5000,  # €50.00 in cents
        currency="EUR",
        idempotency_key="sepa-payment-001",
        region="DE",  # Can be any SEPA zone country
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.SEPA_DEBIT,
            bank_details=BankDetails(
                iban="DE89370400440532013000",
                bic="COBADEFFXXX",  # Optional
            ),
            customer=CustomerDetails(
                name="Max Mustermann",
                email="max@example.com",
            ),
            return_url="https://example.com/payment/complete",
        ),
        metadata={"subscription_id": "sub-67890"},
    )
    
    response = connector.process_local_payment(request)
    print(f"SEPA Debit Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# Boleto (Brazil)
# =============================================================================
def create_boleto_payment():
    """
    Boleto Bancário is a popular payment method in Brazil.
    A voucher is generated that customers can pay at banks, ATMs, or online.
    
    Required fields:
    - Customer name and tax_id (CPF for individuals, CNPJ for companies)
    - Customer address (for voucher generation)
    
    Note: Boleto is an async payment method - the payment is not instant.
    The response will include payment_instructions with the boleto barcode/voucher URL.
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=15000,  # R$150.00 in centavos
        currency="BRL",
        idempotency_key="boleto-payment-001",
        region="BR",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.BOLETO,
            customer=CustomerDetails(
                name="João Silva",
                email="joao@example.com",
                tax_id="12345678909",  # CPF number
                address_line1="Rua Augusta, 1234",
                city="São Paulo",
                state="SP",
                postal_code="01304-000",
                country="BR",
            ),
            return_url="https://example.com/payment/complete",
        ),
        statement_descriptor="Loja ABC",
    )
    
    response = connector.process_local_payment(request)
    print(f"Boleto Payment Response: {response.model_dump_json(indent=2)}")
    # Display response.payment_instructions to customer (barcode, voucher URL)
    return response


# =============================================================================
# PIX (Brazil)
# =============================================================================
def create_pix_payment():
    """
    PIX is Brazil's instant payment system.
    Customers scan a QR code or copy a payment code to complete payment.
    
    Required fields:
    - Customer email
    
    Note: PIX payments are near-instant but still asynchronous.
    The response includes a QR code for the customer to scan.
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=5000,  # R$50.00 in centavos
        currency="BRL",
        idempotency_key="pix-payment-001",
        region="BR",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.PIX,
            customer=CustomerDetails(
                email="maria@example.com",
                name="Maria Santos",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"PIX Payment Response: {response.model_dump_json(indent=2)}")
    # Display response.payment_instructions QR code to customer
    return response


# =============================================================================
# Bancontact (Belgium)
# =============================================================================
def create_bancontact_payment():
    """
    Bancontact is the most popular debit card payment method in Belgium.
    Customers are redirected to Bancontact to authenticate with their bank.
    
    Required fields:
    - return_url: URL to redirect after payment completion
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=3500,  # €35.00 in cents
        currency="EUR",
        idempotency_key="bancontact-payment-001",
        region="BE",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.BANCONTACT,
            customer=CustomerDetails(
                name="Jan Janssen",
                email="jan@example.be",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"Bancontact Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# giropay (Germany)
# =============================================================================
def create_giropay_payment():
    """
    giropay is an online payment method used in Germany.
    Customers are redirected to their bank to complete the payment.
    
    Required fields:
    - return_url: URL to redirect after payment completion
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=4500,  # €45.00 in cents
        currency="EUR",
        idempotency_key="giropay-payment-001",
        region="DE",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.GIROPAY,
            customer=CustomerDetails(
                name="Hans Schmidt",
                email="hans@example.de",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"giropay Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# EPS (Austria)
# =============================================================================
def create_eps_payment():
    """
    EPS is an online transfer payment method popular in Austria.
    Customers are redirected to their bank to authorize the payment.
    
    Required fields:
    - return_url: URL to redirect after payment completion
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=7500,  # €75.00 in cents
        currency="EUR",
        idempotency_key="eps-payment-001",
        region="AT",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.EPS,
            customer=CustomerDetails(
                name="Franz Gruber",
                email="franz@example.at",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"EPS Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# P24 / Przelewy24 (Poland)
# =============================================================================
def create_p24_payment():
    """
    Przelewy24 (P24) is a popular payment method in Poland.
    Customers can choose from multiple Polish banks and payment methods.
    
    Required fields:
    - Customer email (required by P24)
    - return_url: URL to redirect after payment completion
    - Optionally bank_code for specific bank selection
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=10000,  # 100 PLN in groszy
        currency="PLN",
        idempotency_key="p24-payment-001",
        region="PL",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.P24,
            customer=CustomerDetails(
                name="Anna Kowalski",
                email="anna@example.pl",
            ),
            bank_details=BankDetails(bank_code="ing"),  # Optional
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"P24 Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# OXXO (Mexico)
# =============================================================================
def create_oxxo_payment():
    """
    OXXO is a voucher-based payment method in Mexico.
    Customers receive a voucher that can be paid at OXXO convenience stores.
    
    Required fields:
    - Customer email (to receive voucher)
    - Customer name
    
    Note: OXXO is an async payment method with a voucher valid for several days.
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=50000,  # 500 MXN in centavos
        currency="MXN",
        idempotency_key="oxxo-payment-001",
        region="MX",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.OXXO,
            customer=CustomerDetails(
                name="Carlos García",
                email="carlos@example.mx",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"OXXO Payment Response: {response.model_dump_json(indent=2)}")
    # Display response.payment_instructions voucher to customer
    return response


# =============================================================================
# Klarna (Multiple Regions)
# =============================================================================
def create_klarna_payment():
    """
    Klarna offers "Buy Now, Pay Later" options in multiple countries.
    Customers can pay in installments or pay later without upfront payment.
    
    Required fields:
    - Customer details (name, email, address)
    - return_url: URL to redirect after Klarna checkout
    
    Note: Klarna is available in US, UK, DE, AT, NL, BE, SE, NO, FI, DK, and more.
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=15000,  # $150.00 in cents
        currency="USD",
        idempotency_key="klarna-payment-001",
        region="US",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.KLARNA,
            customer=CustomerDetails(
                name="John Doe",
                email="john@example.com",
                phone="+14155551234",
                address_line1="123 Main St",
                city="San Francisco",
                state="CA",
                postal_code="94102",
                country="US",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"Klarna Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# BACS Direct Debit (UK)
# =============================================================================
def create_bacs_debit_payment():
    """
    BACS Direct Debit is used for recurring payments in the UK.
    Requires customer's bank account details (sort code and account number).
    
    Required fields:
    - sort_code: UK bank sort code
    - account_number: UK bank account number
    - Customer name
    
    Note: BACS payments take 3-5 business days to clear.
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=5000,  # £50.00 in pence
        currency="GBP",
        idempotency_key="bacs-payment-001",
        region="GB",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.BACS_DEBIT,
            bank_details=BankDetails(
                sort_code="108800",
                account_number="00012345",
            ),
            customer=CustomerDetails(
                name="James Smith",
                email="james@example.co.uk",
                address_line1="10 Downing Street",
                city="London",
                postal_code="SW1A 2AA",
                country="GB",
            ),
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"BACS Debit Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# Alipay (China)
# =============================================================================
def create_alipay_payment():
    """
    Alipay is one of China's largest digital payment platforms.
    Customers scan a QR code or are redirected to Alipay to complete payment.
    
    Required fields:
    - return_url: URL to redirect after payment completion
    """
    os.environ.setdefault("STRIPE_API_KEY", "")
    connector = StripeConnector()
    
    request = LocalPaymentRequest(
        amount=10000,  # ¥100.00 in fen
        currency="CNY",
        idempotency_key="alipay-payment-001",
        region="CN",
        local_payment_method=LocalPaymentMethod(
            type=LocalPaymentMethodType.ALIPAY,
            return_url="https://example.com/payment/complete",
        ),
    )
    
    response = connector.process_local_payment(request)
    print(f"Alipay Payment Response: {response.model_dump_json(indent=2)}")
    return response


# =============================================================================
# Helper Functions
# =============================================================================
def list_available_payment_methods_for_region(region: str):
    """
    List all available local payment methods for a specific region.
    
    Args:
        region: ISO 3166-1 alpha-2 country code (e.g., 'NL', 'BR', 'DE')
    """
    methods = get_supported_payment_methods(region)
    print(f"\nAvailable payment methods for {region}:")
    for method in methods:
        print(f"  - {method.value}")
    return methods


def check_payment_method_availability(region: str, payment_type: LocalPaymentMethodType):
    """
    Check if a payment method is available in a specific region.
    
    Args:
        region: ISO 3166-1 alpha-2 country code
        payment_type: The payment method type to check
    """
    try:
        validate_region_payment_method(region, payment_type)
        print(f"✓ {payment_type.value} is available in {region}")
        return True
    except ValueError as e:
        print(f"✗ {e}")
        return False


# =============================================================================
# Main Example
# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Local Payment Methods Examples")
    print("=" * 60)
    
    # List available payment methods for different regions
    regions_to_check = ["NL", "BR", "DE", "PL", "GB", "US", "MX"]
    for region in regions_to_check:
        list_available_payment_methods_for_region(region)
    
    print("\n" + "=" * 60)
    print("Payment Method Availability Checks")
    print("=" * 60)
    
    # Check specific payment method availability
    check_payment_method_availability("NL", LocalPaymentMethodType.IDEAL)
    check_payment_method_availability("NL", LocalPaymentMethodType.BOLETO)  # Should fail
    check_payment_method_availability("BR", LocalPaymentMethodType.BOLETO)
    check_payment_method_availability("BR", LocalPaymentMethodType.PIX)
    check_payment_method_availability("DE", LocalPaymentMethodType.GIROPAY)
    check_payment_method_availability("GB", LocalPaymentMethodType.BACS_DEBIT)
    
    print("\n" + "=" * 60)
    print("Note: To run actual payment examples, set STRIPE_API_KEY")
    print("environment variable with your Stripe test key.")
    print("=" * 60)
