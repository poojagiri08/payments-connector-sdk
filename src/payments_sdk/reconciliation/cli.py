#!/usr/bin/env python3
"""Command-line interface for reconciliation tools.

This CLI provides commands to run payment reconciliation jobs
between the local database and payment service providers.

Usage:
    python -m payments_sdk.reconciliation.cli reconcile --start 2024-01-01 --end 2024-01-31
    python -m payments_sdk.reconciliation.cli reconcile --start 2024-01-01T00:00:00 --end 2024-01-31T23:59:59 --output report.json
"""

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timedelta
from typing import Optional

from ..database import (
    Base,
    create_async_engine,
    get_async_session_factory,
    get_database_url,
)
from .models import ReconciliationRequest
from .service import ReconciliationService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def parse_datetime(dt_string: str) -> datetime:
    """Parse datetime string in various formats.
    
    Args:
        dt_string: Datetime string in ISO format or date format.
    
    Returns:
        Parsed datetime object.
    
    Raises:
        ValueError: If the string cannot be parsed.
    """
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(dt_string, fmt)
        except ValueError:
            continue
    
    raise ValueError(
        f"Unable to parse datetime: {dt_string}. "
        f"Expected formats: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"
    )


async def run_reconciliation_async(
    start_time: datetime,
    end_time: datetime,
    provider: str = "stripe",
    output_file: Optional[str] = None,
    output_format: str = "json",
    include_details: bool = True,
) -> int:
    """Run reconciliation asynchronously.
    
    Args:
        start_time: Start of reconciliation time range.
        end_time: End of reconciliation time range.
        provider: PSP provider name.
        output_file: Optional output file path.
        output_format: Output format ('json', 'csv', 'text', 'detailed_text').
        include_details: Include detailed records in output.
    
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    database_url = get_database_url()
    engine = create_async_engine(database_url=database_url)
    
    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    session_factory = get_async_session_factory(engine)
    
    try:
        async with session_factory() as session:
            service = ReconciliationService(session)
            
            request = ReconciliationRequest(
                start_time=start_time,
                end_time=end_time,
                provider=provider,
                include_details=include_details,
            )
            
            logger.info(f"Starting reconciliation from {start_time} to {end_time}")
            report = await service.run_reconciliation(request)
            
            # Generate output
            output = service.generate_report(
                report=report,
                format=output_format,
                include_details=include_details,
            )
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                logger.info(f"Report written to {output_file}")
            else:
                print(output)
            
            # Return exit code based on reconciliation status
            if report.status.value == "completed":
                if report.total_unmatched > 0 or report.total_discrepancies > 0:
                    logger.warning(
                        f"Reconciliation completed with issues: "
                        f"{report.total_unmatched} unmatched, "
                        f"{report.total_discrepancies} discrepancies"
                    )
                    return 1
                return 0
            else:
                logger.error(f"Reconciliation failed: {report.error_message}")
                return 2
    
    finally:
        await engine.dispose()


def run_reconciliation(
    start_time: datetime,
    end_time: datetime,
    provider: str = "stripe",
    output_file: Optional[str] = None,
    output_format: str = "json",
    include_details: bool = True,
) -> int:
    """Run reconciliation (sync wrapper).
    
    Args:
        start_time: Start of reconciliation time range.
        end_time: End of reconciliation time range.
        provider: PSP provider name.
        output_file: Optional output file path.
        output_format: Output format.
        include_details: Include detailed records.
    
    Returns:
        Exit code.
    """
    return asyncio.run(run_reconciliation_async(
        start_time=start_time,
        end_time=end_time,
        provider=provider,
        output_file=output_file,
        output_format=output_format,
        include_details=include_details,
    ))


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI.
    
    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="reconciliation",
        description="Payment reconciliation tools for comparing local and PSP records.",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Reconcile command
    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Run a reconciliation job",
    )
    reconcile_parser.add_argument(
        "--start", "-s",
        required=True,
        help="Start date/time (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)",
    )
    reconcile_parser.add_argument(
        "--end", "-e",
        required=True,
        help="End date/time (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)",
    )
    reconcile_parser.add_argument(
        "--provider", "-p",
        default="stripe",
        help="PSP provider (default: stripe)",
    )
    reconcile_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    reconcile_parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "text", "detailed_text"],
        default="json",
        help="Output format (default: json)",
    )
    reconcile_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only include summary statistics, not detailed records",
    )
    
    return parser


def main(args: Optional[list] = None) -> int:
    """Main entry point for the CLI.
    
    Args:
        args: Optional list of command-line arguments (for testing).
    
    Returns:
        Exit code.
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    if not parsed_args.command:
        parser.print_help()
        return 1
    
    if parsed_args.command == "reconcile":
        try:
            start_time = parse_datetime(parsed_args.start)
            end_time = parse_datetime(parsed_args.end)
            
            # If only date is provided, set end_time to end of day
            if start_time == end_time and "T" not in parsed_args.end:
                end_time = end_time + timedelta(days=1) - timedelta(seconds=1)
            
        except ValueError as e:
            logger.error(str(e))
            return 1
        
        return run_reconciliation(
            start_time=start_time,
            end_time=end_time,
            provider=parsed_args.provider,
            output_file=parsed_args.output,
            output_format=parsed_args.format,
            include_details=not parsed_args.summary_only,
        )
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
