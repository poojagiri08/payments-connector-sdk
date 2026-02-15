# Security Vulnerability Analysis Report

## Payments Connector SDK

**Report Date:** June 2025  
**Repository:** payments-connector-sdk  
**Analysis Type:** Comprehensive Security Audit

---

## Executive Summary

This security analysis evaluates the payments-connector-sdk repository, a Python-based payment processing SDK that integrates with Stripe and potentially other payment service providers (PSPs). The codebase demonstrates a modular approach to payment processing with a FastAPI-based reference API.

### Overall Security Posture: **MODERATE RISK**

The codebase exhibits several security concerns ranging from critical to low severity:
- **3 Critical** issues requiring immediate attention
- **4 High** severity vulnerabilities
- **5 Medium** severity issues
- **3 Low** severity findings

**Key Concerns:**
1. Optional webhook signature verification poses significant security risk
2. Missing authentication/authorization on all API endpoints
3. Flexible dependency versions may include vulnerable packages
4. Sensitive data exposure in raw provider responses
5. Missing CORS, rate limiting, and security headers configuration

---

## Categorized Vulnerabilities

### 🔴 CRITICAL (Requires Immediate Action)

#### 1. Optional Webhook Signature Verification (CRITICAL)

**Location:** `src/payments_sdk/connectors/stripe_connector.py:79-91`

**Description:**  
The webhook signature verification is optional and can be bypassed if `STRIPE_WEBHOOK_SECRET` is not configured. The code explicitly states "best effort parse (not recommended for production)" when the secret is missing.

```python
def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if webhook_secret:
        # ... verification logic ...
    else:
        # best effort parse (not recommended for production)
        event = stripe.Event.construct_from(stripe.util.json.loads(body), stripe.api_key)
```

**Risk:** An attacker can forge webhook payloads to:
- Trigger false payment confirmations
- Manipulate payment statuses
- Cause financial fraud by marking unpaid orders as paid

**Remediation:**
```python
def parse_webhook(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise ValueError("STRIPE_WEBHOOK_SECRET must be configured for production use")
    sig_header = headers.get("stripe-signature", "")
    if not sig_header:
        raise ValueError("Missing stripe-signature header")
    try:
        event = stripe.Webhook.construct_event(payload=body, sig_header=sig_header, secret=webhook_secret)
    except stripe.error.SignatureVerificationError as e:
        raise ValueError("Invalid webhook signature") from e
    return {"type": event.type, "provider": "stripe", "payload": event.to_dict()}
```

---

#### 2. Missing Authentication/Authorization on All Endpoints (CRITICAL)

**Location:** `src/payments_sdk/api.py:23-62`

**Description:**  
All API endpoints (`/payments`, `/payments/{id}/capture`, `/payments/{id}/refund`, `/webhooks/psp`) are publicly accessible without any authentication or authorization mechanisms.

```python
@app.post("/payments")
async def create_payment(body: CreatePaymentBody, x_provider: Optional[str] = Header("stripe")):
    # No authentication check
    connector = CONNECTORS.get(x_provider)
```

**Risk:**
- Unauthorized payment creation
- Fraudulent captures and refunds
- Denial of service through payment request flooding
- Complete compromise of payment processing functionality

**Remediation:**
```python
from fastapi import Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    api_key = credentials.credentials
    expected_key = os.getenv("API_KEY")
    if not expected_key or api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

@app.post("/payments")
async def create_payment(
    body: CreatePaymentBody, 
    x_provider: Optional[str] = Header("stripe"),
    api_key: str = Depends(verify_api_key)
):
    # Authenticated request handling
```

---

#### 3. Flexible Dependency Versions with Known CVEs (CRITICAL)

**Location:** `requirements.txt:1-6`

**Description:**  
Dependencies are specified with minimum version constraints (>=) rather than pinned versions, allowing installation of potentially vulnerable package versions.

```
fastapi>=0.95
uvicorn[standard]>=0.22
pydantic>=1.10
stripe>=5.0.0
httpx>=0.24
pytest>=7.0
```

**Known CVEs:**

| Package | CVE | Severity | Description | Affected Versions |
|---------|-----|----------|-------------|-------------------|
| Starlette (FastAPI dep) | CVE-2024-47874 | High (7.5) | DoS via unbounded multipart/form-data parsing | < 0.40.0 |
| FastAPI | CVE-2024-24762 | High | ReDoS via Content-Type header | Older versions |
| Pydantic | CVE-2024-3772 | Medium (5.3) | ReDoS via crafted email strings | < 2.4.0, < 1.10.13 |
| Starlette | CVE-2023-30798 | High (7.5) | DoS via excessive multipart form fields | < 0.25.0 |
| Starlette | CVE-2023-29159 | High (7.5) | Directory traversal vulnerability | < 0.27.0 |

**Remediation:**
```
# requirements.txt - Pin to secure versions
fastapi==0.115.6
uvicorn[standard]==0.32.1
pydantic==2.10.3
stripe==11.3.0
httpx==0.28.1
pytest==8.3.4
starlette==0.41.3
```

---

### 🟠 HIGH (Address Soon)

#### 4. Sensitive Data Exposure in Raw Provider Response (HIGH)

**Location:** `src/payments_sdk/connectors/stripe_connector.py:43-44, 48-49`

**Description:**  
The `client_secret` and full raw provider responses are returned to the API caller, potentially exposing sensitive payment data through logs or client-side storage.

```python
mfa = {"type": "3ds", "client_secret": pi.client_secret}
return PaymentResponse(
    id=pi.id,
    status=status,
    raw_provider_response=pi.to_dict(),  # Exposes sensitive data
    mfa=mfa,
)
```

**Risk:**
- Payment tokens and secrets could be logged
- Sensitive financial data exposed to front-end applications
- Compliance issues with PCI-DSS requirements

**Remediation:**
```python
def _sanitize_response(self, raw_response: dict) -> dict:
    """Remove sensitive fields from provider response"""
    sensitive_fields = ['client_secret', 'payment_method', 'source', 'customer']
    sanitized = {k: v for k, v in raw_response.items() if k not in sensitive_fields}
    return sanitized

return PaymentResponse(
    id=pi.id,
    status=status,
    raw_provider_response=self._sanitize_response(pi.to_dict()),
    mfa={"type": "3ds", "redirect_url": generate_3ds_url(pi.id)} if pi.status == "requires_action" else None,
)
```

---

#### 5. API Key Set at Module Level (HIGH)

**Location:** `src/payments_sdk/connectors/stripe_connector.py:6`

**Description:**  
The Stripe API key is set at module import time, creating a global side effect that affects all instances and cannot be easily changed or tested.

```python
stripe.api_key = os.getenv("STRIPE_API_KEY", "")
```

**Risk:**
- Difficult to isolate for testing
- Cannot use different API keys for different merchants
- May be cached/logged during module loading
- Potential for API key leakage in stack traces

**Remediation:**
```python
class StripeConnector(ConnectorBase):
    def __init__(self, api_key: str = None):
        self._api_key = api_key or os.getenv("STRIPE_API_KEY")
        if not self._api_key:
            raise ValueError("STRIPE_API_KEY must be provided")
    
    def _get_client(self) -> stripe:
        """Get configured stripe client"""
        stripe.api_key = self._api_key
        return stripe
```

---

#### 6. Insufficient Input Validation on Payment Amounts (HIGH)

**Location:** `src/payments_sdk/api.py:32-48`

**Description:**  
The capture and refund endpoints accept `amount` from an untyped dict without proper validation.

```python
@app.post("/payments/{payment_id}/capture")
async def capture_payment(payment_id: str, body: dict, x_provider: Optional[str] = Header("stripe")):
    amount = int(body.get("amount", 0))  # No validation
```

**Risk:**
- Negative amounts could be processed
- Integer overflow with extremely large values
- Type coercion errors with non-numeric input
- Partial capture with 0 amount could lead to unexpected behavior

**Remediation:**
```python
from pydantic import BaseModel, Field, validator

class CaptureBody(BaseModel):
    amount: int = Field(..., gt=0, le=99999999)  # 999,999.99 max
    
    @validator('amount')
    def validate_amount(cls, v):
        if v <= 0:
            raise ValueError('Amount must be positive')
        return v

@app.post("/payments/{payment_id}/capture")
async def capture_payment(
    payment_id: str, 
    body: CaptureBody, 
    x_provider: Optional[str] = Header("stripe")
):
    resp = connector.capture(payment_id, body.amount)
```

---

#### 7. Information Disclosure in Error Responses (HIGH)

**Location:** `src/payments_sdk/connectors/stripe_connector.py:51-53, 61-62`

**Description:**  
Full exception messages are returned to callers, potentially exposing internal system details.

```python
except stripe.error.StripeError as e:
    return PaymentResponse(id=None, status="failed", raw_provider_response={"error": str(e)})
```

**Risk:**
- Stack traces and internal errors could be exposed
- Attackers can map internal systems from error messages
- Sensitive API paths or configurations may be revealed

**Remediation:**
```python
import logging

logger = logging.getLogger(__name__)

def _handle_stripe_error(self, e: stripe.error.StripeError) -> PaymentResponse:
    """Safely handle Stripe errors without exposing internals"""
    logger.error(f"Stripe error: {e}", exc_info=True)
    
    error_mapping = {
        stripe.error.CardError: "card_error",
        stripe.error.RateLimitError: "rate_limit",
        stripe.error.InvalidRequestError: "invalid_request",
        stripe.error.AuthenticationError: "authentication_error",
    }
    
    error_type = error_mapping.get(type(e), "payment_error")
    return PaymentResponse(
        id=None, 
        status="failed", 
        raw_provider_response={"error_type": error_type, "message": "Payment processing failed"}
    )
```

---

### 🟡 MEDIUM (Plan to Address)

#### 8. Missing CORS Configuration (MEDIUM)

**Location:** `src/payments_sdk/api.py:7`

**Description:**  
The FastAPI application has no CORS (Cross-Origin Resource Sharing) middleware configured, leaving it either completely open or completely restricted depending on defaults.

```python
app = FastAPI(title="Payments Connector - Reference API")
# No CORSMiddleware
```

**Risk:**
- API may be accessible from any origin
- Cross-site request forgery (CSRF) potential
- Unauthorized cross-origin access to payment data

**Remediation:**
```python
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Payments Connector - Reference API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["X-Provider", "Authorization", "Content-Type"],
)
```

---

#### 9. Missing Rate Limiting (MEDIUM)

**Location:** `src/payments_sdk/api.py`

**Description:**  
No rate limiting is implemented on any endpoint, making the API vulnerable to abuse and denial of service attacks.

**Risk:**
- API abuse and resource exhaustion
- Brute force attacks on payment endpoints
- Cost explosion from fraudulent payment attempts
- Denial of service

**Remediation:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/payments")
@limiter.limit("10/minute")
async def create_payment(request: Request, body: CreatePaymentBody, ...):
    # Rate limited endpoint
```

---

#### 10. Missing Security Headers (MEDIUM)

**Location:** `src/payments_sdk/api.py`

**Description:**  
No security headers are configured for the API responses.

**Risk:**
- Clickjacking potential
- MIME type sniffing attacks
- Missing XSS protection headers

**Remediation:**
```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

#### 11. Idempotency Key Not Enforced (MEDIUM)

**Location:** `src/payments_sdk/api.py:14-21`, `src/payments_sdk/connectors/stripe_connector.py:20-50`

**Description:**  
The `idempotency_key` field is optional and not passed to the Stripe API, leading to potential duplicate payment processing.

```python
class CreatePaymentBody(BaseModel):
    idempotency_key: Optional[str] = None  # Optional, not enforced

# In stripe_connector.py - idempotency_key not used in PaymentIntent.create()
```

**Risk:**
- Duplicate charges from retry logic
- Race conditions in payment processing
- Financial reconciliation issues

**Remediation:**
```python
def authorize(self, request: PaymentRequest) -> PaymentResponse:
    if not request.idempotency_key:
        raise ValueError("idempotency_key is required for payment processing")
    
    pi = stripe.PaymentIntent.create(
        amount=request.amount,
        currency=request.currency.lower(),
        payment_method=request.payment_method.get("token"),
        idempotency_key=request.idempotency_key,  # Pass to Stripe
        ...
    )
```

---

#### 12. Payment ID Path Parameter Not Validated (MEDIUM)

**Location:** `src/payments_sdk/api.py:32-48`

**Description:**  
The `payment_id` path parameter is used directly without validation of format or existence.

```python
@app.post("/payments/{payment_id}/capture")
async def capture_payment(payment_id: str, ...):
    # payment_id not validated
    resp = connector.capture(payment_id, amount)
```

**Risk:**
- Injection attacks through malformed payment IDs
- Processing of invalid or non-existent payments
- Information disclosure through error messages

**Remediation:**
```python
import re

def validate_payment_id(payment_id: str) -> str:
    """Validate Stripe PaymentIntent ID format"""
    if not re.match(r'^pi_[a-zA-Z0-9]{24}$', payment_id):
        raise HTTPException(status_code=400, detail="Invalid payment ID format")
    return payment_id

@app.post("/payments/{payment_id}/capture")
async def capture_payment(
    payment_id: str = Depends(validate_payment_id),
    ...
):
```

---

### 🟢 LOW (Consider Addressing)

#### 13. Template Connector Stores API Key as Instance Variable (LOW)

**Location:** `src/payments_sdk/connectors/template.py:9-10`

**Description:**  
The template connector stores the API key directly as an instance attribute, which could be exposed in debug output.

```python
def __init__(self, api_key: str):
    self.api_key = api_key
```

**Risk:**
- API key exposed in object serialization
- Key visible in debug/repr output
- Potential exposure in logging

**Remediation:**
```python
def __init__(self, api_key: str):
    self._api_key = api_key  # Private attribute
    
def __repr__(self):
    return f"<TemplateConnector configured={bool(self._api_key)}>"
```

---

#### 14. Example Code Sets Empty API Key (LOW)

**Location:** `examples/merchant_example.py:10`

**Description:**  
The example sets an empty string as the default API key, which could be copied to production code.

```python
os.environ.setdefault("STRIPE_API_KEY", "")  # set your test key in env
```

**Risk:**
- Developers may copy this pattern
- Empty key could lead to silent failures

**Remediation:**
```python
# examples/merchant_example.py
import os
import sys

def run():
    api_key = os.environ.get("STRIPE_API_KEY")
    if not api_key:
        print("ERROR: STRIPE_API_KEY environment variable must be set")
        print("Get your test key from: https://dashboard.stripe.com/test/apikeys")
        sys.exit(1)
```

---

#### 15. Missing Request Logging/Audit Trail (LOW)

**Location:** `src/payments_sdk/api.py`

**Description:**  
No request logging or audit trail mechanism is implemented for payment operations.

**Risk:**
- Difficulty in investigating fraudulent transactions
- Compliance issues with financial regulations
- No forensic evidence for security incidents

**Remediation:**
```python
import logging
import uuid
from fastapi import Request

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("audit")

@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    audit_logger.info(f"[{request_id}] {request.method} {request.url.path} from {request.client.host}")
    response = await call_next(request)
    audit_logger.info(f"[{request_id}] Response: {response.status_code}")
    return response
```

---

## Hardcoded Credentials Check

### ✅ No Hardcoded Secrets Found

A comprehensive search of the codebase revealed **no hardcoded API keys, secrets, or credentials**.

**Positive Findings:**
- `STRIPE_API_KEY` properly sourced from environment variable
- `STRIPE_WEBHOOK_SECRET` properly sourced from environment variable
- No test API keys (`sk_test_*`, `pk_test_*`) found in source code
- No configuration files containing secrets

**Files Scanned:**
- `src/payments_sdk/connectors/stripe_connector.py`
- `src/payments_sdk/connectors/template.py`
- `src/payments_sdk/api.py`
- `examples/merchant_example.py`
- `.github/workflows/ci.yml`
- `requirements.txt`
- `openapi.yaml`

---

## Data Handling Assessment

### Payment Tokens and Sensitive Data

| Data Type | Current Handling | Risk Level | Recommendation |
|-----------|------------------|------------|----------------|
| `payment_method.token` | Passed to Stripe API | Low | ✅ Appropriate - tokenized data |
| `client_secret` | Exposed in MFA response | Medium | Filter from client responses |
| `raw_provider_response` | Full object returned | High | Sanitize sensitive fields |
| `stripe.api_key` | Global variable | Medium | Instance-level configuration |

### Transmission Security

**Current State:**
- No explicit HTTPS enforcement
- OpenAPI spec shows `http://localhost:8000` as server URL
- No TLS configuration in uvicorn setup

**Recommendation:**
```yaml
# openapi.yaml
servers:
  - url: https://api.example.com
    description: Production API (TLS required)
  - url: http://localhost:8000
    description: Local development only
```

---

## Remediation Priority Matrix

| Priority | Vulnerability | Effort | Impact |
|----------|--------------|--------|--------|
| 🔴 P0 | Mandatory webhook verification | Low | Critical |
| 🔴 P0 | Add authentication to endpoints | Medium | Critical |
| 🔴 P0 | Pin dependency versions | Low | Critical |
| 🟠 P1 | Sanitize raw provider responses | Low | High |
| 🟠 P1 | Instance-level API key config | Medium | High |
| 🟠 P1 | Input validation on amounts | Low | High |
| 🟠 P1 | Safe error handling | Low | High |
| 🟡 P2 | Add CORS middleware | Low | Medium |
| 🟡 P2 | Implement rate limiting | Medium | Medium |
| 🟡 P2 | Add security headers | Low | Medium |
| 🟡 P2 | Enforce idempotency keys | Low | Medium |
| 🟡 P2 | Validate payment ID format | Low | Medium |
| 🟢 P3 | Private API key attributes | Low | Low |
| 🟢 P3 | Fix example code patterns | Low | Low |
| 🟢 P3 | Add audit logging | Medium | Low |

---

## Compliance Considerations

### PCI-DSS Relevance

While this SDK properly avoids handling raw PANs (relying on Stripe tokenization), several findings may impact PCI-DSS compliance:

1. **Requirement 3.4**: Ensure `client_secret` and raw responses don't contain PAN data
2. **Requirement 6.5**: Input validation weaknesses identified
3. **Requirement 8**: Authentication missing on all endpoints
4. **Requirement 10**: Audit trail not implemented

### GDPR Considerations

- Payment metadata may contain personal data
- No data retention or deletion mechanisms visible
- Logging recommendations should consider data minimization

---

## Conclusion

The payments-connector-sdk demonstrates good foundational security practices (environment-based secrets, tokenization reliance) but requires significant hardening before production deployment. The most critical issues—optional webhook verification and missing authentication—should be addressed immediately as they represent direct financial and security risks.

**Recommended Next Steps:**
1. Implement mandatory webhook signature verification
2. Add API authentication layer
3. Pin all dependencies to known-secure versions
4. Conduct penetration testing after remediation
5. Implement monitoring and alerting for security events

---

*This report was generated through static code analysis and dependency review. Dynamic testing and penetration testing are recommended for comprehensive security validation.*
