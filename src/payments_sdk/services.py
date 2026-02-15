"""Payment service layer that integrates API operations with database persistence."""

import logging
from typing import Optional, Dict, Any, List

from sqlalchemy.ext.asyncio import AsyncSession

from .database import (
    Payment,
    PaymentRepository,
    IdempotencyKeyRepository,
    TransactionHistoryRepository,
    PaymentStatus,
    TransactionAction,
)
from .connectors.base import PaymentRequest, PaymentResponse

logger = logging.getLogger(__name__)


class PaymentService:
    """Service class for payment operations with persistence."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the service with a database session.
        
        Args:
            session: AsyncSession instance for database operations.
        """
        self.session = session
        self.payment_repo = PaymentRepository(session)
        self.idempotency_repo = IdempotencyKeyRepository(session)
        self.history_repo = TransactionHistoryRepository(session)
    
    async def check_idempotency(
        self,
        idempotency_key: str,
        endpoint: str,
        request_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Check if a request with this idempotency key has been processed.
        
        Args:
            idempotency_key: The idempotency key from the request.
            endpoint: The API endpoint being called.
            request_data: The request data for conflict detection.
        
        Returns:
            Cached response if found and valid, None for new requests.
        
        Raises:
            ValueError: If the idempotency key conflicts with a previous request.
        """
        existing, is_conflict = await self.idempotency_repo.check_idempotency(
            key=idempotency_key,
            endpoint=endpoint,
            request_data=request_data,
        )
        
        if is_conflict:
            raise ValueError(
                f"Idempotency key '{idempotency_key}' has already been used "
                f"for a different request"
            )
        
        if existing and existing.response_data:
            logger.info(f"Returning cached response for idempotency key {idempotency_key}")
            return existing.response_data
        
        return None
    
    async def create_payment(
        self,
        request: PaymentRequest,
        provider_response: PaymentResponse,
        provider: str,
        idempotency_key: str,
    ) -> Payment:
        """Create a new payment record with the provider response.
        
        Args:
            request: The original payment request.
            provider_response: Response from the payment provider.
            provider: Payment provider name.
            idempotency_key: Idempotency key for this request.
        
        Returns:
            Created Payment instance.
        """
        # Map provider status to our canonical status
        status = self._map_provider_status(provider_response.status)
        
        # Create payment record
        payment = await self.payment_repo.create(
            amount=request.amount,
            currency=request.currency,
            provider=provider,
            merchant_id=request.merchant_id,
            metadata=request.metadata,
            status=status,
        )
        
        # Update with provider transaction ID
        if provider_response.provider_transaction_id:
            payment.provider_transaction_id = provider_response.provider_transaction_id
        if provider_response.raw_provider_response:
            payment.raw_provider_response = provider_response.raw_provider_response
        
        # Handle captured amount for capture_immediate intent
        if status == PaymentStatus.CAPTURED.value:
            payment.captured_amount = request.amount
        
        await self.session.flush()
        
        # Record transaction history
        await self.history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.AUTHORIZE.value,
            new_status=status,
            amount=request.amount,
            provider_response_code=provider_response.provider_response_code,
        )
        
        # Store idempotency key with response
        request_hash = self.idempotency_repo.compute_request_hash(request.model_dump())
        response_data = provider_response.model_dump()
        response_data['internal_payment_id'] = payment.id
        
        await self.idempotency_repo.create(
            key=idempotency_key,
            endpoint="/payments",
            payment_id=payment.id,
            response_data=response_data,
            response_status_code=200,
            request_hash=request_hash,
        )
        
        logger.info(f"Created payment {payment.id} with status {status}")
        return payment
    
    async def capture_payment(
        self,
        provider_transaction_id: str,
        amount: int,
        provider_response: PaymentResponse,
        idempotency_key: str,
    ) -> Payment:
        """Record a payment capture operation.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
            amount: Amount captured.
            provider_response: Response from the payment provider.
            idempotency_key: Idempotency key for this request.
        
        Returns:
            Updated Payment instance.
        
        Raises:
            ValueError: If payment not found.
        """
        payment = await self.payment_repo.get_by_provider_transaction_id(
            provider_transaction_id
        )
        
        if not payment:
            # Create a minimal payment record if we don't have one
            logger.warning(
                f"Payment not found for provider_transaction_id {provider_transaction_id}, "
                "creating record from capture"
            )
            payment = await self.payment_repo.create(
                amount=amount,
                currency="USD",  # Default, will be updated
                provider="stripe",
                status=PaymentStatus.AUTHORIZED.value,
            )
            payment.provider_transaction_id = provider_transaction_id
            await self.session.flush()
        
        previous_status = payment.status
        new_status = self._map_provider_status(provider_response.status)
        
        # Update payment status and captured amount
        await self.payment_repo.update_status(
            payment=payment,
            new_status=new_status,
            raw_provider_response=provider_response.raw_provider_response,
        )
        await self.payment_repo.update_capture_amount(payment, amount)
        
        # Record transaction history
        await self.history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.CAPTURE.value,
            previous_status=previous_status,
            new_status=new_status,
            amount=amount,
            provider_response_code=provider_response.provider_response_code,
        )
        
        # Store idempotency key
        response_data = provider_response.model_dump()
        response_data['internal_payment_id'] = payment.id
        await self.idempotency_repo.create(
            key=idempotency_key,
            endpoint=f"/payments/{provider_transaction_id}/capture",
            payment_id=payment.id,
            response_data=response_data,
            response_status_code=200,
        )
        
        logger.info(f"Captured {amount} for payment {payment.id}")
        return payment
    
    async def refund_payment(
        self,
        provider_transaction_id: str,
        amount: int,
        provider_response: PaymentResponse,
        idempotency_key: str,
    ) -> Payment:
        """Record a payment refund operation.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
            amount: Amount refunded.
            provider_response: Response from the payment provider.
            idempotency_key: Idempotency key for this request.
        
        Returns:
            Updated Payment instance.
        
        Raises:
            ValueError: If payment not found.
        """
        payment = await self.payment_repo.get_by_provider_transaction_id(
            provider_transaction_id
        )
        
        if not payment:
            raise ValueError(f"Payment not found for {provider_transaction_id}")
        
        previous_status = payment.status
        
        # Update refund amount (this also updates status)
        await self.payment_repo.update_refund_amount(payment, amount)
        
        # Record transaction history
        await self.history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.REFUND.value,
            previous_status=previous_status,
            new_status=payment.status,
            amount=amount,
            provider_response_code=provider_response.provider_response_code,
        )
        
        # Store idempotency key
        response_data = provider_response.model_dump()
        response_data['internal_payment_id'] = payment.id
        await self.idempotency_repo.create(
            key=idempotency_key,
            endpoint=f"/payments/{provider_transaction_id}/refund",
            payment_id=payment.id,
            response_data=response_data,
            response_status_code=200,
        )
        
        logger.info(f"Refunded {amount} for payment {payment.id}")
        return payment
    
    async def void_payment(
        self,
        provider_transaction_id: str,
        provider_response: PaymentResponse,
        idempotency_key: str,
    ) -> Payment:
        """Record a payment void operation.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
            provider_response: Response from the payment provider.
            idempotency_key: Idempotency key for this request.
        
        Returns:
            Updated Payment instance.
        
        Raises:
            ValueError: If payment not found.
        """
        payment = await self.payment_repo.get_by_provider_transaction_id(
            provider_transaction_id
        )
        
        if not payment:
            raise ValueError(f"Payment not found for {provider_transaction_id}")
        
        previous_status = payment.status
        new_status = PaymentStatus.VOIDED.value
        
        # Update payment status
        await self.payment_repo.update_status(
            payment=payment,
            new_status=new_status,
            raw_provider_response=provider_response.raw_provider_response,
        )
        
        # Record transaction history
        await self.history_repo.create(
            payment_id=payment.id,
            action=TransactionAction.VOID.value,
            previous_status=previous_status,
            new_status=new_status,
            provider_response_code=provider_response.provider_response_code,
        )
        
        # Store idempotency key
        response_data = provider_response.model_dump()
        response_data['internal_payment_id'] = payment.id
        await self.idempotency_repo.create(
            key=idempotency_key,
            endpoint=f"/payments/{provider_transaction_id}/void",
            payment_id=payment.id,
            response_data=response_data,
            response_status_code=200,
        )
        
        logger.info(f"Voided payment {payment.id}")
        return payment
    
    async def update_payment_from_3ds(
        self,
        provider_transaction_id: str,
        provider_response: PaymentResponse,
        idempotency_key: str,
        is_initiation: bool = False,
    ) -> Payment:
        """Update payment status based on 3DS flow.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
            provider_response: Response from the payment provider.
            idempotency_key: Idempotency key for this request.
            is_initiation: True if initiating 3DS, False if completing.
        
        Returns:
            Updated Payment instance.
        """
        payment = await self.payment_repo.get_by_provider_transaction_id(
            provider_transaction_id
        )
        
        if not payment:
            raise ValueError(f"Payment not found for {provider_transaction_id}")
        
        previous_status = payment.status
        new_status = self._map_provider_status(provider_response.status)
        
        # Update payment status
        await self.payment_repo.update_status(
            payment=payment,
            new_status=new_status,
            raw_provider_response=provider_response.raw_provider_response,
        )
        
        # Record transaction history
        action = (
            TransactionAction.MFA_INITIATED.value 
            if is_initiation 
            else TransactionAction.MFA_COMPLETED.value
        )
        await self.history_repo.create(
            payment_id=payment.id,
            action=action,
            previous_status=previous_status,
            new_status=new_status,
            provider_response_code=provider_response.provider_response_code,
        )
        
        # Store idempotency key for complete endpoint
        if not is_initiation:
            response_data = provider_response.model_dump()
            response_data['internal_payment_id'] = payment.id
            await self.idempotency_repo.create(
                key=idempotency_key,
                endpoint=f"/payments/{provider_transaction_id}/3ds/complete",
                payment_id=payment.id,
                response_data=response_data,
                response_status_code=200,
            )
        
        return payment
    
    async def get_payment(self, payment_id: str) -> Optional[Payment]:
        """Get a payment by internal ID.
        
        Args:
            payment_id: Internal payment ID.
        
        Returns:
            Payment instance if found, None otherwise.
        """
        return await self.payment_repo.get_by_id(payment_id)
    
    async def get_payment_by_provider_id(
        self, 
        provider_transaction_id: str
    ) -> Optional[Payment]:
        """Get a payment by provider transaction ID.
        
        Args:
            provider_transaction_id: Provider's transaction ID.
        
        Returns:
            Payment instance if found, None otherwise.
        """
        return await self.payment_repo.get_by_provider_transaction_id(
            provider_transaction_id
        )
    
    async def get_payment_history(
        self, 
        payment_id: str
    ) -> List[Dict[str, Any]]:
        """Get transaction history for a payment.
        
        Args:
            payment_id: Internal payment ID.
        
        Returns:
            List of transaction history records.
        """
        history = await self.history_repo.get_by_payment_id(payment_id)
        return [h.to_dict() for h in history]
    
    async def list_payments_by_merchant(
        self,
        merchant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List payments for a merchant.
        
        Args:
            merchant_id: Merchant identifier.
            limit: Maximum number of results.
            offset: Offset for pagination.
        
        Returns:
            List of payment records.
        """
        payments = await self.payment_repo.list_by_merchant(
            merchant_id=merchant_id,
            limit=limit,
            offset=offset,
        )
        return [p.to_dict() for p in payments]
    
    def _map_provider_status(self, provider_status: str) -> str:
        """Map provider-specific status to canonical status.
        
        Args:
            provider_status: Status from the payment provider.
        
        Returns:
            Canonical PaymentStatus value.
        """
        status_mapping = {
            # Stripe status mappings
            "requires_capture": PaymentStatus.AUTHORIZED.value,
            "requires_action": PaymentStatus.PENDING_MFA.value,
            "requires_payment_method": PaymentStatus.FAILED.value,
            "succeeded": PaymentStatus.CAPTURED.value,
            "canceled": PaymentStatus.VOIDED.value,
            "processing": PaymentStatus.PENDING.value,
            # Canonical statuses pass through
            "authorized": PaymentStatus.AUTHORIZED.value,
            "captured": PaymentStatus.CAPTURED.value,
            "failed": PaymentStatus.FAILED.value,
            "pending_mfa": PaymentStatus.PENDING_MFA.value,
            "voided": PaymentStatus.VOIDED.value,
            "refunded": PaymentStatus.REFUNDED.value,
            "partially_refunded": PaymentStatus.PARTIALLY_REFUNDED.value,
        }
        return status_mapping.get(provider_status, PaymentStatus.PENDING.value)
