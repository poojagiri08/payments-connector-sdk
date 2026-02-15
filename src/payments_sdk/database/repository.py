"""Repository layer for payment persistence operations."""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from . import models
from .models import Payment, IdempotencyKey, TransactionHistory, PaymentStatus, TransactionAction

logger = logging.getLogger(__name__)

DEFAULT_IDEMPOTENCY_TTL_HOURS = 24


class PaymentRepository:
    """Repository for Payment CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(
        self,
        amount: int,
        currency: str,
        status: str = PaymentStatus.PENDING.value,
        provider: str = "stripe",
        provider_transaction_id: Optional[str] = None,
        merchant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_provider_response: Optional[Dict[str, Any]] = None,
    ) -> Payment:
        """
        Create a new payment record.
        
        Args:
            amount: Payment amount in smallest currency unit.
            currency: Three-letter ISO currency code.
            status: Payment status.
            provider: Payment provider name.
            provider_transaction_id: Provider's transaction ID.
            merchant_id: Merchant identifier.
            metadata: Additional metadata.
            raw_provider_response: Raw response from provider.
        
        Returns:
            Created Payment instance.
        """
        payment = Payment(
            amount=amount,
            currency=currency,
            status=status,
            provider=provider,
            provider_transaction_id=provider_transaction_id,
            merchant_id=merchant_id,
        )
        
        if metadata:
            payment.payment_metadata = metadata
        if raw_provider_response:
            payment.raw_provider_response = raw_provider_response
        
        self.session.add(payment)
        await self.session.flush()
        await self.session.refresh(payment)
        
        logger.info(f"Created payment {payment.id} with status {status}")
        return payment
    
    async def get_by_id(self, payment_id: str) -> Optional[Payment]:
        """
        Get a payment by its ID.
        
        Args:
            payment_id: Payment identifier.
        
        Returns:
            Payment instance or None if not found.
        """
        result = await self.session.execute(
            select(Payment).where(Payment.id == payment_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_provider_transaction_id(
        self, provider_transaction_id: str
    ) -> Optional[Payment]:
        """
        Get a payment by provider transaction ID.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
        
        Returns:
            Payment instance or None if not found.
        """
        result = await self.session.execute(
            select(Payment).where(
                Payment.provider_transaction_id == provider_transaction_id
            )
        )
        return result.scalar_one_or_none()
    
    async def update_status(
        self,
        payment_id: str,
        new_status: str,
        raw_provider_response: Optional[Dict[str, Any]] = None,
    ) -> Optional[Payment]:
        """
        Update a payment's status.
        
        Args:
            payment_id: Payment identifier.
            new_status: New status value.
            raw_provider_response: Updated provider response.
        
        Returns:
            Updated Payment instance or None if not found.
        """
        payment = await self.get_by_id(payment_id)
        if payment is None:
            return None
        
        old_status = payment.status
        payment.status = new_status
        payment.updated_at = datetime.utcnow()
        
        if raw_provider_response:
            payment.raw_provider_response = raw_provider_response
        
        await self.session.flush()
        await self.session.refresh(payment)
        
        logger.info(
            f"Updated payment {payment_id} status from {old_status} to {new_status}"
        )
        return payment
    
    async def update_capture_amount(
        self,
        payment_id: str,
        captured_amount: int,
    ) -> Optional[Payment]:
        """
        Update a payment's captured amount.
        
        Args:
            payment_id: Payment identifier.
            captured_amount: New captured amount.
        
        Returns:
            Updated Payment instance or None if not found.
        """
        payment = await self.get_by_id(payment_id)
        if payment is None:
            return None
        
        payment.captured_amount = captured_amount
        payment.updated_at = datetime.utcnow()
        
        await self.session.flush()
        await self.session.refresh(payment)
        
        logger.info(
            f"Updated payment {payment_id} captured_amount to {captured_amount}"
        )
        return payment
    
    async def update_refund_amount(
        self,
        payment_id: str,
        refunded_amount: int,
    ) -> Optional[Payment]:
        """
        Update a payment's refunded amount.
        
        Args:
            payment_id: Payment identifier.
            refunded_amount: New refunded amount.
        
        Returns:
            Updated Payment instance or None if not found.
        """
        payment = await self.get_by_id(payment_id)
        if payment is None:
            return None
        
        payment.refunded_amount = refunded_amount
        payment.updated_at = datetime.utcnow()
        
        await self.session.flush()
        await self.session.refresh(payment)
        
        logger.info(
            f"Updated payment {payment_id} refunded_amount to {refunded_amount}"
        )
        return payment
    
    async def list_by_merchant(
        self,
        merchant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Payment]:
        """
        List payments for a merchant.
        
        Args:
            merchant_id: Merchant identifier.
            limit: Maximum number of results.
            offset: Number of results to skip.
        
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
        """
        List payments by status.
        
        Args:
            status: Payment status to filter by.
            limit: Maximum number of results.
            offset: Number of results to skip.
        
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
        self.session = session
    
    @staticmethod
    def compute_request_hash(request_data: Dict[str, Any]) -> str:
        """
        Compute a hash of the request data for idempotency checking.
        
        Args:
            request_data: Request data to hash.
        
        Returns:
            SHA-256 hash of the request data.
        """
        import json
        data_str = json.dumps(request_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    async def get_by_key(self, key: str) -> Optional[IdempotencyKey]:
        """
        Get an idempotency key record by its key.
        
        Args:
            key: Idempotency key string.
        
        Returns:
            IdempotencyKey instance or None if not found.
        """
        result = await self.session.execute(
            select(IdempotencyKey).where(IdempotencyKey.key == key)
        )
        return result.scalar_one_or_none()
    
    async def create(
        self,
        key: str,
        endpoint: str,
        request_data: Dict[str, Any],
        payment_id: Optional[str] = None,
        ttl_hours: int = DEFAULT_IDEMPOTENCY_TTL_HOURS,
    ) -> IdempotencyKey:
        """
        Create a new idempotency key record.
        
        Args:
            key: Idempotency key string.
            endpoint: API endpoint.
            request_data: Request data.
            payment_id: Associated payment ID.
            ttl_hours: Time-to-live in hours.
        
        Returns:
            Created IdempotencyKey instance.
        """
        request_hash = self.compute_request_hash(request_data)
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
        
        idempotency_key = IdempotencyKey(
            key=key,
            payment_id=payment_id,
            endpoint=endpoint,
            request_hash=request_hash,
            expires_at=expires_at,
        )
        
        self.session.add(idempotency_key)
        await self.session.flush()
        await self.session.refresh(idempotency_key)
        
        logger.info(f"Created idempotency key {key}")
        return idempotency_key
    
    async def update_response(
        self,
        key: str,
        response_data: Dict[str, Any],
        status_code: int,
        payment_id: Optional[str] = None,
    ) -> Optional[IdempotencyKey]:
        """
        Update an idempotency key with the response data.
        
        Args:
            key: Idempotency key string.
            response_data: Response data to store.
            status_code: HTTP status code.
            payment_id: Associated payment ID.
        
        Returns:
            Updated IdempotencyKey instance or None if not found.
        """
        idempotency_key = await self.get_by_key(key)
        if idempotency_key is None:
            return None
        
        idempotency_key.response_data = response_data
        idempotency_key.response_status_code = status_code
        if payment_id:
            idempotency_key.payment_id = payment_id
        
        await self.session.flush()
        await self.session.refresh(idempotency_key)
        
        logger.info(f"Updated idempotency key {key} with response")
        return idempotency_key
    
    async def delete_expired(self) -> int:
        """
        Delete all expired idempotency keys.
        
        Returns:
            Number of deleted records.
        """
        from sqlalchemy import delete
        
        result = await self.session.execute(
            delete(IdempotencyKey).where(
                IdempotencyKey.expires_at < datetime.utcnow()
            )
        )
        count = result.rowcount
        
        if count > 0:
            logger.info(f"Deleted {count} expired idempotency keys")
        
        return count
    
    async def check_idempotency(
        self,
        key: str,
        request_data: Dict[str, Any],
    ) -> tuple[Optional[IdempotencyKey], bool]:
        """
        Check if a request is idempotent.
        
        Args:
            key: Idempotency key string.
            request_data: Request data to compare.
        
        Returns:
            Tuple of (IdempotencyKey or None, is_valid: bool).
            - If no existing key, returns (None, True).
            - If existing key with matching hash and response, returns (key, True).
            - If existing key with different hash, returns (key, False).
        """
        existing = await self.get_by_key(key)
        
        if existing is None:
            return (None, True)
        
        if existing.is_expired:
            # Expired keys can be reused
            await self.session.delete(existing)
            await self.session.flush()
            return (None, True)
        
        # Compare request hashes
        request_hash = self.compute_request_hash(request_data)
        if existing.request_hash != request_hash:
            # Same key, different request - conflict
            return (existing, False)
        
        # Same key, same request - return cached response if available
        return (existing, True)


class TransactionHistoryRepository:
    """Repository for TransactionHistory CRUD operations."""
    
    def __init__(self, session: AsyncSession):
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
        """
        Create a new transaction history record.
        
        Args:
            payment_id: Associated payment ID.
            action: Action type (authorize, capture, refund, etc.).
            new_status: New status after the action.
            previous_status: Status before the action.
            amount: Amount involved in the action.
            provider_response_code: Response code from provider.
            error_message: Error message if action failed.
            action_metadata: Additional metadata.
        
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
        await self.session.refresh(history)
        
        logger.info(
            f"Created transaction history for payment {payment_id}: {action}"
        )
        return history
    
    async def get_by_payment_id(
        self,
        payment_id: str,
        limit: int = 100,
    ) -> List[TransactionHistory]:
        """
        Get transaction history for a payment.
        
        Args:
            payment_id: Payment identifier.
            limit: Maximum number of results.
        
        Returns:
            List of TransactionHistory instances, ordered by created_at desc.
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
        """
        Get transaction history for a specific action type.
        
        Args:
            payment_id: Payment identifier.
            action: Action type to filter by.
        
        Returns:
            List of TransactionHistory instances.
        """
        result = await self.session.execute(
            select(TransactionHistory)
            .where(
                and_(
                    TransactionHistory.payment_id == payment_id,
                    TransactionHistory.action == action,
                )
            )
            .order_by(TransactionHistory.created_at.desc())
        )
        return list(result.scalars().all())
