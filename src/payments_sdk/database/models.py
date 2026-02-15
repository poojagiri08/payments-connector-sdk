"""SQLAlchemy models for payment persistence."""

import uuid
import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    Index,
    UniqueConstraint,
    Enum as SQLEnum,
)
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.dialects.sqlite import JSON
import enum


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class PaymentStatus(str, enum.Enum):
    """Canonical payment statuses."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    FAILED = "failed"
    PENDING_MFA = "pending_mfa"
    VOIDED = "voided"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"


class TransactionAction(str, enum.Enum):
    """Types of transaction actions tracked in history."""
    AUTHORIZE = "authorize"
    CAPTURE = "capture"
    REFUND = "refund"
    VOID = "void"
    MFA_INITIATED = "mfa_initiated"
    MFA_COMPLETED = "mfa_completed"


class Payment(Base):
    """Payment model to store transaction states."""
    __tablename__ = "payments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=PaymentStatus.PENDING.value)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    provider_transaction_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, default="stripe")
    merchant_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Amount tracking
    captured_amount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    refunded_amount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # JSON fields stored as text
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_provider_response_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    transaction_history: Mapped[List["TransactionHistory"]] = relationship(
        "TransactionHistory",
        back_populates="payment",
        cascade="all, delete-orphan",
        order_by="TransactionHistory.created_at.desc()",
    )
    idempotency_keys: Mapped[List["IdempotencyKey"]] = relationship(
        "IdempotencyKey",
        back_populates="payment",
        cascade="all, delete-orphan",
    )

    # Table indexes
    __table_args__ = (
        Index("ix_payments_status", "status"),
        Index("ix_payments_created_at", "created_at"),
        Index("ix_payments_merchant_id", "merchant_id"),
    )

    @property
    def payment_metadata(self) -> Optional[Dict[str, Any]]:
        """Parse metadata from JSON string."""
        if self.metadata_json:
            try:
                return json.loads(self.metadata_json)
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    @payment_metadata.setter
    def payment_metadata(self, value: Optional[Dict[str, Any]]) -> None:
        """Serialize metadata to JSON string."""
        if value is not None:
            self.metadata_json = json.dumps(value)
        else:
            self.metadata_json = None

    @property
    def raw_provider_response(self) -> Optional[Dict[str, Any]]:
        """Parse raw provider response from JSON string."""
        if self.raw_provider_response_json:
            try:
                return json.loads(self.raw_provider_response_json)
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    @raw_provider_response.setter
    def raw_provider_response(self, value: Optional[Dict[str, Any]]) -> None:
        """Serialize raw provider response to JSON string."""
        if value is not None:
            self.raw_provider_response_json = json.dumps(value)
        else:
            self.raw_provider_response_json = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert payment to dictionary representation."""
        return {
            "id": self.id,
            "status": self.status,
            "amount": self.amount,
            "currency": self.currency,
            "provider_transaction_id": self.provider_transaction_id,
            "provider": self.provider,
            "merchant_id": self.merchant_id,
            "captured_amount": self.captured_amount,
            "refunded_amount": self.refunded_amount,
            "metadata": self.payment_metadata,
            "raw_provider_response": self.raw_provider_response,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IdempotencyKey(Base):
    """Model for storing idempotency keys to support idempotent requests."""
    __tablename__ = "idempotency_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    payment_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("payments.id"), nullable=True)
    response_data_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    payment: Mapped[Optional["Payment"]] = relationship("Payment", back_populates="idempotency_keys")

    # Table indexes
    __table_args__ = (
        Index("ix_idempotency_keys_expires_at", "expires_at"),
    )

    @property
    def response_data(self) -> Optional[Dict[str, Any]]:
        """Parse response data from JSON string."""
        if self.response_data_json:
            try:
                return json.loads(self.response_data_json)
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    @response_data.setter
    def response_data(self, value: Optional[Dict[str, Any]]) -> None:
        """Serialize response data to JSON string."""
        if value is not None:
            self.response_data_json = json.dumps(value)
        else:
            self.response_data_json = None

    @property
    def is_expired(self) -> bool:
        """Check if the idempotency key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class TransactionHistory(Base):
    """Model for tracking transaction history and state transitions."""
    __tablename__ = "transaction_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    payment_id: Mapped[str] = mapped_column(String(36), ForeignKey("payments.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    new_status: Mapped[str] = mapped_column(String(50), nullable=False)
    amount: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    provider_response_code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action_metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    payment: Mapped["Payment"] = relationship("Payment", back_populates="transaction_history")

    # Table indexes
    __table_args__ = (
        Index("ix_transaction_history_action", "action"),
        Index("ix_transaction_history_created_at", "created_at"),
    )

    @property
    def action_metadata(self) -> Optional[Dict[str, Any]]:
        """Parse action metadata from JSON string."""
        if self.action_metadata_json:
            try:
                return json.loads(self.action_metadata_json)
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    @action_metadata.setter
    def action_metadata(self, value: Optional[Dict[str, Any]]) -> None:
        """Serialize action metadata to JSON string."""
        if value is not None:
            self.action_metadata_json = json.dumps(value)
        else:
            self.action_metadata_json = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction history to dictionary representation."""
        return {
            "id": self.id,
            "payment_id": self.payment_id,
            "action": self.action,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "amount": self.amount,
            "provider_response_code": self.provider_response_code,
            "error_message": self.error_message,
            "action_metadata": self.action_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
