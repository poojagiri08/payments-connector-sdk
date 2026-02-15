"""Repository layer for payment persistence operations."""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Payment,
    IdempotencyKey,
    TransactionHistory,
    PaymentStatus,
    TransactionAction,
)

logger = logging.getLogger(__name__)

# Default idempotency key TTL in hours
DEFAULT_IDEMPOTENCY_TTL_HOURS = 24


class PaymentRepository:
    """Repository for Payment CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the repository with a database session.
        
        Args:
            session: AsyncSession instance for database operations.
        """
        self.session = session
    
    async def create(
        self,
        amount: int,
        currency: str,
        provider: str = "stripe",
        merchant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = PaymentStatus.PENDING.value,
    ) -> Payment:
        """Create a new payment record.
        
        Args:
            amount: Payment amount in minor units.
            currency: Three-letter currency code.
            provider: Payment provider name.
            merchant_id: Optional merchant identifier.
            metadata: Optional metadata dictionary.
            status: Initial payment status.
        
        Returns:
            Created Payment instance.
        """
        payment = Payment(
            amount=amount,
            currency=currency.upper(),
            provider=provider,
            merchant_id=merchant_id,
            status=status,
        )
        if metadata:
            payment.metadata = metadata
        
        self.session.add(payment)
        await self.session.flush()
        
        logger.info(f"Created payment {payment.id} with status {status}")
        return payment
    
    async def get_by_id(self, payment_id: str) -> Optional[Payment]:
        """Get a payment by its ID.
        
        Args:
            payment_id: Payment ID.
        
        Returns:
            Payment instance if found, None otherwise.
        """
        result = await self.session.execute(
            select(Payment).where(Payment.id == payment_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_provider_transaction_id(
        self,
        provider_transaction_id: str
    ) -> Optional[Payment]:
        """Get a payment by provider transaction ID.
        
        Args:
            provider_transaction_id: Provider's transaction identifier.
        
        Returns:
            Payment instance if found, None otherwise.
        """
        result = await self.session.execute(
            select(Payment).where(
                Payment.provider_transaction_id == provider_transaction_id
            )
        )
        return result.scalar_one_or_none()
    
    async def update_status(
        self,
        payment: Payment,
        new_status: str,
        provider_transaction_id: Optional[str] = None,
        raw_provider_response: Optional[Dict[str, Any]] = None,
    ) -> Payment:
        """Update payment status and optionally provider transaction ID.
        
        Args:
            payment: Payment instance to update.
            new_status: New payment status.
            provider_transaction_id: Optional provider transaction ID to set.
            raw_provider_response: Optional raw provider response.
        
        Returns:
            Updated Payment instance.
        """
        payment.status = new_status
        payment.updated_at = datetime.utcnow()
        
        if provider_transaction_id:
            payment.provider_transaction_id = provider_transaction_id
        
        if raw_provider_response is not None:
            payment.raw_provider_response = raw_provider_response
        
        await self.session.flush()
        logger.info(f"Updated payment {payment.id} status to {new_status}")
        return payment
    
    async def update_capture_amount(
        self,
        payment: Payment,
        capture_amount: int
    ) -> Payment:
        """Update the captured amount for a payment.
        
        Args:
            payment: Payment instance to update.
            capture_amount: Amount captured.
        
        Returns:
            Updated Payment instance.
        """
        payment.captured_amount = payment.captured_amount + capture_amount
        payment.updated_at = datetime.utcnow()
        await self.session.flush()
        return payment
    
    async def update_refund_amount(
        self,
        payment: Payment,
        refund_amount: int
    ) -> Payment:
        """Update the refunded amount for a payment.
        
        Args:
            payment: Payment instance to update.
            refund_amount: Amount refunded.
        
        Returns:
            Updated Payment instance.
        """
        payment.refunded_amount = payment.refunded_amount + refund_amount
        payment.updated_at = datetime.utcnow()
        
        # Update status based on refund state
        if payment.refunded_amount >= payment.captured_amount:
            payment.status = PaymentStatus.REFUNDED.value
        else:
            payment.status = PaymentStatus.PARTIALLY_REFUNDED.value
        
        await self.session.flush()
        return payment
    
    async def list_by_merchant(
        self,
        merchant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Payment]:
        """List payments for a merchant.
        
        Args:
            merchant_id: Merchant identifier.
            limit: Maximum number of results.
            offset: Offset for pagination.
        
        Returns:
            List of Payment instances.
        """
        result = await self.session.execute(
            select(Payment)
            .where(Payment.merchant_id == merchant_id)
            .order_by(Payment.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())
    
    async def list_by_status(
        self,
        status: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Payment]:
        """List payments by status.
        
        Args:
            status: Payment status to filter by.
            limit: Maximum number of results.
            offset: Offset for pagination.
        
        Returns:
            List of Payment instances.
        """
        result = await self.session.execute(
            select(Payment)
            .where(Payment.status == status)
            .order_by(Payment.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())


class IdempotencyKeyRepository:
    """Repository for IdempotencyKey CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the repository with a database session.
        
        Args:
            session: AsyncSession instance for database operations.
        """
        self.session = session
    
    @staticmethod
    def compute_request_hash(request_data: Dict[str, Any]) -> str:
        """Compute a hash of the request data for conflict detection.
        
        Args:
            request_data: Request data dictionary.
        
        Returns:
            SHA256 hash of the request data.
        """
        import json
        data_str = json.dumps(request_data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    async def get_by_key(self, key: str) -> Optional[IdempotencyKey]:
        """Get an idempotency key record by key value.
        
        Args:
            key: The idempotency key string.
        
        Returns:
            IdempotencyKey instance if found, None otherwise.
        """
        result = await self.session.execute(
            select(IdempotencyKey).where(IdempotencyKey.key == key)
        )
        return result.scalar_one_or_none()
    
    async def create(
        self,
        key: str,
        endpoint: str,
        payment_id: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
        response_status_code: int = 200,
        request_hash: Optional[str] = None,
        ttl_hours: int = DEFAULT_IDEMPOTENCY_TTL_HOURS,
    ) -> IdempotencyKey:
        """Create a new idempotency key record.
        
        Args:
            key: The idempotency key string.
            endpoint: The endpoint that was called.
            payment_id: Optional associated payment ID.
            response_data: Optional response data to cache.
            response_status_code: HTTP status code of the response.
            request_hash: Optional hash of the request data.
            ttl_hours: Time-to-live in hours.
        
        Returns:
            Created IdempotencyKey instance.
        """
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
        
        idempotency_key = IdempotencyKey(
            key=key,
            endpoint=endpoint,
            payment_id=payment_id,
            response_status_code=response_status_code,
            request_hash=request_hash,
            expires_at=expires_at,
        )
        if response_data:
            idempotency_key.response_data = response_data
        
        self.session.add(idempotency_key)
        await self.session.flush()
        
        logger.debug(f"Created idempotency key {key} for endpoint {endpoint}")
        return idempotency_key
    
    async def update_response(
        self,
        idempotency_key: IdempotencyKey,
        payment_id: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
        response_status_code: int = 200,
    ) -> IdempotencyKey:
        """Update an idempotency key with response data.
        
        Args:
            idempotency_key: IdempotencyKey instance to update.
            payment_id: Optional payment ID to associate.
            response_data: Response data to cache.
            response_status_code: HTTP status code.
        
        Returns:
            Updated IdempotencyKey instance.
        """
        if payment_id:
            idempotency_key.payment_id = payment_id
        if response_data:
            idempotency_key.response_data = response_data
        idempotency_key.response_status_code = response_status_code
        
        await self.session.flush()
        return idempotency_key
    
    async def delete_expired(self) -> int:
        """Delete expired idempotency keys.
        
        Returns:
            Number of deleted records.
        """
        from sqlalchemy import delete
        
        result = await self.session.execute(
            delete(IdempotencyKey).where(
                IdempotencyKey.expires_at < datetime.utcnow()
            )
        )
        await self.session.flush()
        return result.rowcount
    
    async def check_idempotency(
        self,
        key: str,
        endpoint: str,
        request_data: Dict[str, Any],
    ) -> tuple[Optional[IdempotencyKey], bool]:
        """Check if an idempotency key exists and is valid.
        
        Args:
            key: The idempotency key string.
            endpoint: The endpoint being called.
            request_data: The request data for conflict detection.
        
        Returns:
            Tuple of (IdempotencyKey or None, is_conflict).
            If IdempotencyKey is returned and is_conflict is False, replay the cached response.
            If is_conflict is True, the request conflicts with a previous request.
            If IdempotencyKey is None, this is a new request.
        """
        existing = await self.get_by_key(key)
        
        if existing is None:
            return None, False
        
        # Check if expired
        if existing.is_expired():
            # Delete expired key and treat as new request
            await self.session.delete(existing)
            await self.session.flush()
            return None, False
        
        # Check for endpoint mismatch
        if existing.endpoint != endpoint:
            logger.warning(
                f"Idempotency key {key} used for different endpoint: "
                f"expected {existing.endpoint}, got {endpoint}"
            )
            return existing, True
        
        # Check for request data conflict
        if existing.request_hash:
            current_hash = self.compute_request_hash(request_data)
            if existing.request_hash != current_hash:
                logger.warning(
                    f"Idempotency key {key} request data mismatch"
                )
                return existing, True
        
        # Valid cached response
        return existing, False


class TransactionHistoryRepository:
    """Repository for TransactionHistory CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the repository with a database session.
        
        Args:
            session: AsyncSession instance for database operations.
        """
        self.session = session
    
    async def create(
        self,
        payment_id: str,
        action: str,
        new_status: str,
        previous_status: Optional[str] = None,
        amount: Optional[int] = None,
        provider_response_code: Optional[str] = None,
        error_message: Optional[str] = None,
        action_metadata: Optional[Dict[str, Any]] = None,
    ) -> TransactionHistory:
        """Create a new transaction history record.
        
        Args:
            payment_id: Associated payment ID.
            action: Action performed (authorize, capture, refund, void).
            new_status: Status after the action.
            previous_status: Status before the action.
            amount: Amount involved in this action.
            provider_response_code: Provider's response code.
            error_message: Error message if action failed.
            action_metadata: Additional metadata for this action.
        
        Returns:
            Created TransactionHistory instance.
        """
        history = TransactionHistory(
            payment_id=payment_id,
            action=action,
            new_status=new_status,
            previous_status=previous_status,
            amount=amount,
            provider_response_code=provider_response_code,
            error_message=error_message,
        )
        if action_metadata:
            history.action_metadata = action_metadata
        
        self.session.add(history)
        await self.session.flush()
        
        logger.debug(
            f"Created transaction history for payment {payment_id}: "
            f"{action} -> {new_status}"
        )
        return history
    
    async def get_by_payment_id(
        self,
        payment_id: str,
        limit: int = 100,
    ) -> List[TransactionHistory]:
        """Get transaction history for a payment.
        
        Args:
            payment_id: Payment ID to get history for.
            limit: Maximum number of results.
        
        Returns:
            List of TransactionHistory instances ordered by creation time desc.
        """
        result = await self.session.execute(
            select(TransactionHistory)
            .where(TransactionHistory.payment_id == payment_id)
            .order_by(TransactionHistory.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
    
    async def get_by_action(
        self,
        payment_id: str,
        action: str,
    ) -> List[TransactionHistory]:
        """Get transaction history for a specific action.
        
        Args:
            payment_id: Payment ID.
            action: Action type to filter by.
        
        Returns:
            List of TransactionHistory instances for the action.
        """
        result = await self.session.execute(
            select(TransactionHistory)
            .where(
                and_(
                    TransactionHistory.payment_id == payment_id,
                    TransactionHistory.action == action
                )
            )
            .order_by(TransactionHistory.created_at.desc())
        )
        return list(result.scalars().all())
