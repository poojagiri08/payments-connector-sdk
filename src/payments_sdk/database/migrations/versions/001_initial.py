"""Initial migration - create payments, idempotency_keys, and transaction_history tables

Revision ID: 001_initial
Revises: 
Create Date: 2026-02-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create payments table
    op.create_table(
        'payments',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('currency', sa.String(3), nullable=False),
        sa.Column('provider_transaction_id', sa.String(255), nullable=True),
        sa.Column('provider', sa.String(50), nullable=False, server_default='stripe'),
        sa.Column('merchant_id', sa.String(255), nullable=True),
        sa.Column('captured_amount', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('refunded_amount', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('raw_provider_response_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    
    # Create indexes for payments
    op.create_index('ix_payments_provider_transaction_id', 'payments', ['provider_transaction_id'])
    op.create_index('ix_payments_status', 'payments', ['status'])
    op.create_index('ix_payments_created_at', 'payments', ['created_at'])
    op.create_index('ix_payments_merchant_id', 'payments', ['merchant_id'])
    
    # Create idempotency_keys table
    op.create_table(
        'idempotency_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('key', sa.String(255), nullable=False, unique=True),
        sa.Column('payment_id', sa.String(36), sa.ForeignKey('payments.id'), nullable=True),
        sa.Column('response_data_json', sa.Text(), nullable=True),
        sa.Column('response_status_code', sa.Integer(), nullable=False, server_default='200'),
        sa.Column('endpoint', sa.String(255), nullable=False),
        sa.Column('request_hash', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
    )
    
    # Create indexes for idempotency_keys
    op.create_index('ix_idempotency_keys_key', 'idempotency_keys', ['key'], unique=True)
    op.create_index('ix_idempotency_keys_expires_at', 'idempotency_keys', ['expires_at'])
    
    # Create transaction_history table
    op.create_table(
        'transaction_history',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('payment_id', sa.String(36), sa.ForeignKey('payments.id'), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('previous_status', sa.String(50), nullable=True),
        sa.Column('new_status', sa.String(50), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=True),
        sa.Column('provider_response_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('action_metadata_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    
    # Create indexes for transaction_history
    op.create_index('ix_transaction_history_payment_id', 'transaction_history', ['payment_id'])
    op.create_index('ix_transaction_history_action', 'transaction_history', ['action'])
    op.create_index('ix_transaction_history_created_at', 'transaction_history', ['created_at'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_transaction_history_created_at', table_name='transaction_history')
    op.drop_index('ix_transaction_history_action', table_name='transaction_history')
    op.drop_index('ix_transaction_history_payment_id', table_name='transaction_history')
    
    op.drop_index('ix_idempotency_keys_expires_at', table_name='idempotency_keys')
    op.drop_index('ix_idempotency_keys_key', table_name='idempotency_keys')
    
    op.drop_index('ix_payments_merchant_id', table_name='payments')
    op.drop_index('ix_payments_created_at', table_name='payments')
    op.drop_index('ix_payments_status', table_name='payments')
    op.drop_index('ix_payments_provider_transaction_id', table_name='payments')
    
    # Drop tables
    op.drop_table('transaction_history')
    op.drop_table('idempotency_keys')
    op.drop_table('payments')
