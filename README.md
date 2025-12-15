```markdown
# payments-connector-sdk (prototype)

A Python-first, connectorized SDK and reference API that provides a canonical integration surface for merchants to integrate with multiple Payment Service Providers (PSPs). Focused on card payments for MVP but designed to be extensible to other local payment methods.

Goals
- Provide a small, stable canonical API for authorization, capture, refunds, voids, and MFA/3DS flows.
- Provide connector templates so contributors can add new PSPs easily.
- Offer a lightweight reference server (FastAPI) and example merchant integrations.
- Avoid handling PANs — rely on PSP tokenization and client-side token flows.

Getting started (quick)
1. python -m venv .venv && source .venv/bin/activate
2. pip install -r requirements.txt
3. export STRIPE_API_KEY="sk_test_..."  # for the example connector
4. uvicorn payments_sdk.api:app --reload
5. Visit the OpenAPI spec at ./openapi.yaml for API reference.

Contributing
- See CONTRIBUTING.md
- We welcome new connectors, tests against PSP sandboxes, and improvements to the simulator and reconciliation tools.

License
- MIT (see LICENSE)
```