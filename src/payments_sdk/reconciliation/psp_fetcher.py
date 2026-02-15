"""PSP transaction fetching module for reconciliation."""

import os
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any

import stripe

from .models import PSPTransaction

logger = logging.getLogger(__name__)


class PSPFetcherBase(ABC):
    """Base class for PSP transaction fetchers."""
    
    @abstractmethod
    def fetch_transactions(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100,
    ) -> List[PSPTransaction]:
        """Fetch transactions from PSP within the given time range.
        
        Args:
            start_time: Start of the time range.
            end_time: End of the time range.
            limit: Maximum number of transactions per batch.
        
        Returns:
            List of PSPTransaction objects.
        """
        raise NotImplementedError
    
    @abstractmethod
    def fetch_transaction_by_id(self, transaction_id: str) -> Optional[PSPTransaction]:
        """Fetch a single transaction by ID.
        
        Args:
            transaction_id: The PSP transaction ID.
        
        Returns:
            PSPTransaction if found, None otherwise.
        """
        raise NotImplementedError


class StripeFetcher(PSPFetcherBase):
    """Stripe transaction fetcher for reconciliation."""
    
    # Fields that should not be included in raw response for security
    SENSITIVE_FIELDS = frozenset([
        'client_secret',
        'payment_method',
        'source',
        'customer',
        'payment_method_details',
        'card',
        'bank_account',
    ])
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the Stripe fetcher.
        
        Args:
            api_key: Stripe API key. Falls back to STRIPE_API_KEY env var.
        
        Raises:
            ValueError: If no API key is provided or found.
        """
        self._api_key = api_key or os.getenv("STRIPE_API_KEY")
        if not self._api_key:
            raise ValueError(
                "STRIPE_API_KEY must be provided either as argument or environment variable"
            )
    
    def _configure_stripe(self) -> None:
        """Configure the Stripe SDK with the API key."""
        stripe.api_key = self._api_key
    
    def _sanitize_response(self, raw_response: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive fields from the raw response.
        
        Args:
            raw_response: Raw response dictionary from Stripe.
        
        Returns:
            Sanitized response dictionary.
        """
        if not raw_response:
            return {}
        sanitized = {}
        for key, value in raw_response.items():
            if key in self.SENSITIVE_FIELDS:
                continue
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_response(value)
            else:
                sanitized[key] = value
        return sanitized
    
    def _map_stripe_status(self, status: str) -> str:
        """Map Stripe status to canonical status.
        
        Args:
            status: Stripe payment intent status.
        
        Returns:
            Canonical status string.
        """
        status_mapping = {
            "requires_payment_method": "pending",
            "requires_confirmation": "pending",
            "requires_action": "pending_mfa",
            "processing": "pending",
            "requires_capture": "authorized",
            "succeeded": "captured",
            "canceled": "voided",
        }
        return status_mapping.get(status, status)
    
    def _convert_to_psp_transaction(
        self,
        payment_intent: Any
    ) -> PSPTransaction:
        """Convert a Stripe PaymentIntent to PSPTransaction.
        
        Args:
            payment_intent: Stripe PaymentIntent object.
        
        Returns:
            PSPTransaction object.
        """
        raw_dict = payment_intent.to_dict() if hasattr(payment_intent, 'to_dict') else {}
        
        return PSPTransaction(
            id=payment_intent.id,
            amount=payment_intent.amount,
            currency=payment_intent.currency.upper(),
            status=self._map_stripe_status(payment_intent.status),
            created_at=datetime.utcfromtimestamp(payment_intent.created),
            metadata=payment_intent.metadata or {},
            raw_data=self._sanitize_response(raw_dict),
        )
    
    def fetch_transactions(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100,
    ) -> List[PSPTransaction]:
        """Fetch PaymentIntents from Stripe within the given time range.
        
        Uses Stripe's list pagination to fetch all matching transactions.
        
        Args:
            start_time: Start of the time range (inclusive).
            end_time: End of the time range (inclusive).
            limit: Maximum number of transactions per API call (max 100).
        
        Returns:
            List of PSPTransaction objects.
        """
        self._configure_stripe()
        
        transactions: List[PSPTransaction] = []
        start_timestamp = int(start_time.timestamp())
        end_timestamp = int(end_time.timestamp())
        
        logger.info(
            f"Fetching Stripe transactions from {start_time.isoformat()} "
            f"to {end_time.isoformat()}"
        )
        
        try:
            # Use auto-pagination to fetch all results
            payment_intents = stripe.PaymentIntent.list(
                created={
                    "gte": start_timestamp,
                    "lte": end_timestamp,
                },
                limit=min(limit, 100),  # Stripe max is 100
            )
            
            for pi in payment_intents.auto_paging_iter():
                transactions.append(self._convert_to_psp_transaction(pi))
            
            logger.info(f"Fetched {len(transactions)} transactions from Stripe")
            return transactions
            
        except stripe.error.AuthenticationError as e:
            logger.error("Stripe authentication failed")
            raise ValueError("Invalid Stripe API key") from e
        except stripe.error.APIConnectionError as e:
            logger.error("Failed to connect to Stripe API")
            raise ConnectionError("Failed to connect to Stripe API") from e
        except stripe.error.StripeError as e:
            logger.error(f"Stripe API error: {type(e).__name__}")
            raise RuntimeError(f"Stripe API error: {e}") from e
    
    def fetch_transaction_by_id(self, transaction_id: str) -> Optional[PSPTransaction]:
        """Fetch a single PaymentIntent by ID.
        
        Args:
            transaction_id: The Stripe PaymentIntent ID.
        
        Returns:
            PSPTransaction if found, None otherwise.
        """
        self._configure_stripe()
        
        try:
            pi = stripe.PaymentIntent.retrieve(transaction_id)
            return self._convert_to_psp_transaction(pi)
        except stripe.error.InvalidRequestError as e:
            if "No such payment_intent" in str(e):
                logger.warning(f"PaymentIntent {transaction_id} not found")
                return None
            raise
        except stripe.error.StripeError as e:
            logger.error(f"Failed to fetch PaymentIntent {transaction_id}: {e}")
            raise RuntimeError(f"Failed to fetch transaction: {e}") from e


def get_psp_fetcher(provider: str = "stripe", api_key: Optional[str] = None) -> PSPFetcherBase:
    """Factory function to get the appropriate PSP fetcher.
    
    Args:
        provider: PSP provider name.
        api_key: Optional API key for the provider.
    
    Returns:
        PSPFetcherBase implementation for the provider.
    
    Raises:
        ValueError: If the provider is not supported.
    """
    fetchers = {
        "stripe": StripeFetcher,
    }
    
    fetcher_class = fetchers.get(provider.lower())
    if not fetcher_class:
        raise ValueError(f"Unsupported PSP provider: {provider}")
    
    return fetcher_class(api_key=api_key)
