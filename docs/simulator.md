# Simulator Connector for Testing

The `SimulatorConnector` provides a complete payment connector implementation for testing without making real PSP API calls. It supports all standard connector operations with configurable behaviors.

## Quick Start

```python
from payments_sdk.connectors import SimulatorConnector, SimulatorConfig, PaymentRequest

# Create simulator with default settings (100% success rate)
connector = SimulatorConnector()

# Or with custom configuration
config = SimulatorConfig(
    success_rate=0.9,      # 90% success rate
    three_ds_rate=0.1,     # 10% chance of 3DS challenge
    delay_ms=100,          # 100ms simulated delay
    timeout_rate=0.05,     # 5% timeout rate
    seed=42                # Reproducible results
)
connector = SimulatorConnector(config=config)
```

## Special Card Tokens

Use these tokens to trigger specific scenarios deterministically:

| Token | Behavior |
|-------|----------|
| `sim_card_success` | Always authorizes successfully |
| `sim_card_decline` | Always declines |
| `sim_card_3ds` | Always requires 3DS challenge |
| `sim_card_insufficient` | Always fails with insufficient funds |
| `sim_card_timeout` | Always raises TimeoutError |

## Usage Examples

### Basic Authorization

```python
request = PaymentRequest(
    amount=1000,
    currency="USD",
    idempotency_key="unique-key-123",
    payment_method={"token": "sim_card_success"}
)
response = connector.authorize(request)
# response.status == "authorized"
```

### 3DS Flow

```python
# Trigger 3DS challenge
request = PaymentRequest(
    amount=1000,
    currency="USD",
    idempotency_key="3ds-test-key",
    payment_method={"token": "sim_card_3ds"}
)
auth_response = connector.authorize(request)
# auth_response.status == "pending_mfa"
# auth_response.mfa == {"type": "3ds", "redirect_url": "/payments/{id}/3ds"}

# Complete 3DS (simulator-specific method)
complete_response = connector.complete_3ds(
    auth_response.provider_transaction_id,
    success=True
)
# complete_response.status == "authorized"
```

### Capture, Refund, Void

```python
# Capture
capture_response = connector.capture(txn_id, amount=1000)

# Refund (full)
refund_response = connector.refund(txn_id, amount=1000)

# Partial refund
partial_refund = connector.refund(txn_id, amount=500)
# partial_refund.status == "partially_refunded"

# Void
void_response = connector.void(txn_id)
```

## Test Utilities

```python
# Get a specific transaction
txn = connector.get_transaction(txn_id)

# Get all transactions
all_txns = connector.get_all_transactions()

# Clear all transactions (for test cleanup)
connector.clear_transactions()

# Health check
health = connector.health_check()
```

## pytest Fixtures

```python
import pytest
from payments_sdk.connectors import SimulatorConnector, SimulatorConfig

@pytest.fixture
def simulator():
    """Provides a fresh simulator for each test."""
    connector = SimulatorConnector()
    yield connector
    connector.clear_transactions()

@pytest.fixture
def simulator_with_failures():
    """Simulator with 50% failure rate."""
    config = SimulatorConfig(success_rate=0.5, seed=42)
    return SimulatorConnector(config=config)

@pytest.fixture
def simulator_with_3ds():
    """Simulator that always requires 3DS."""
    config = SimulatorConfig(three_ds_rate=1.0)
    return SimulatorConnector(config=config)
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `success_rate` | float | 1.0 | Probability of successful authorization (0.0-1.0) |
| `three_ds_rate` | float | 0.0 | Probability of 3DS challenge requirement |
| `delay_ms` | int | 0 | Simulated response delay in milliseconds |
| `timeout_rate` | float | 0.0 | Probability of timeout errors |
| `seed` | int | None | Random seed for reproducible results |

## Notes

- The simulator stores transactions in memory; they do not persist across connector instances
- Use `seed` in `SimulatorConfig` for reproducible test results
- Special card tokens always override random behavior based on config
- The `complete_3ds()` method is simulator-specific and not part of `ConnectorBase`
