"""Report generation for reconciliation results."""

import json
import csv
import io
from datetime import datetime
from typing import Optional

from .models import ReconciliationReport, DiscrepancyType


class ReportGenerator:
    """Generator for reconciliation reports in various formats."""
    
    def __init__(self, report: ReconciliationReport):
        """Initialize the report generator.
        
        Args:
            report: The reconciliation report to generate output from.
        """
        self.report = report
    
    def to_json(self, include_details: bool = True, indent: int = 2) -> str:
        """Generate JSON representation of the report.
        
        Args:
            include_details: If True, include all records. If False, only summary.
            indent: JSON indentation level.
        
        Returns:
            JSON string representation of the report.
        """
        if include_details:
            data = self.report.to_full_dict()
        else:
            data = self.report.to_summary_dict()
        
        # Custom serializer for datetime objects
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, DiscrepancyType):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        return json.dumps(data, indent=indent, default=json_serializer)
    
    def to_csv(self, record_type: str = "all") -> str:
        """Generate CSV representation of specific record types.
        
        Args:
            record_type: Type of records to include ('matched', 'unmatched', 
                        'discrepancies', or 'all').
        
        Returns:
            CSV string with the requested records.
        """
        output = io.StringIO()
        
        if record_type in ("matched", "all"):
            if self.report.matched_records:
                writer = csv.writer(output)
                writer.writerow([
                    "type", "local_id", "psp_id", "amount", "currency", 
                    "status", "matched_at"
                ])
                for record in self.report.matched_records:
                    writer.writerow([
                        "matched",
                        record.local_id,
                        record.psp_id,
                        record.amount,
                        record.currency,
                        record.status,
                        record.matched_at.isoformat(),
                    ])
        
        if record_type in ("unmatched", "all"):
            if self.report.unmatched_records:
                if output.tell() > 0:
                    output.write("\n")
                writer = csv.writer(output)
                if record_type == "unmatched":
                    writer.writerow([
                        "type", "source", "transaction_id", "amount", "currency",
                        "status", "created_at", "reason"
                    ])
                for record in self.report.unmatched_records:
                    writer.writerow([
                        "unmatched",
                        record.source,
                        record.transaction_id,
                        record.amount,
                        record.currency,
                        record.status,
                        record.created_at.isoformat(),
                        record.reason.value,
                    ])
        
        if record_type in ("discrepancies", "all"):
            if self.report.discrepancy_records:
                if output.tell() > 0:
                    output.write("\n")
                writer = csv.writer(output)
                if record_type == "discrepancies":
                    writer.writerow([
                        "type", "local_id", "psp_id", "discrepancy_type",
                        "field_name", "local_value", "psp_value", "detected_at"
                    ])
                for record in self.report.discrepancy_records:
                    writer.writerow([
                        "discrepancy",
                        record.local_id,
                        record.psp_id,
                        record.discrepancy_type.value,
                        record.field_name,
                        str(record.local_value),
                        str(record.psp_value),
                        record.detected_at.isoformat(),
                    ])
        
        return output.getvalue()
    
    def to_summary_text(self) -> str:
        """Generate a human-readable text summary of the report.
        
        Returns:
            Formatted text summary of the reconciliation report.
        """
        summary = self.report.to_summary_dict()
        stats = summary["statistics"]
        
        lines = [
            "=" * 60,
            "RECONCILIATION REPORT SUMMARY",
            "=" * 60,
            f"Report ID: {summary['id']}",
            f"Status: {summary['status']}",
            f"Provider: {summary['provider']}",
            "",
            "Time Range:",
            f"  Start: {summary['start_time']}",
            f"  End: {summary['end_time']}",
            "",
            "Statistics:",
            f"  Total Local Records: {stats['total_local_records']}",
            f"  Total PSP Records: {stats['total_psp_records']}",
            f"  Matched Records: {stats['total_matched']}",
            f"  Unmatched Records: {stats['total_unmatched']}",
            f"  Discrepancies: {stats['total_discrepancies']}",
            f"  Match Rate: {stats['match_rate']}",
            "",
            f"Created At: {summary['created_at']}",
            f"Completed At: {summary['completed_at'] or 'N/A'}",
        ]
        
        if summary.get("error_message"):
            lines.extend([
                "",
                "Error:",
                f"  {summary['error_message']}",
            ])
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def to_detailed_text(self) -> str:
        """Generate a detailed human-readable text report.
        
        Returns:
            Formatted text with summary and all records.
        """
        lines = [self.to_summary_text(), ""]
        
        # Unmatched records
        if self.report.unmatched_records:
            lines.extend([
                "UNMATCHED RECORDS",
                "-" * 40,
            ])
            
            missing_in_local = [
                r for r in self.report.unmatched_records 
                if r.reason == DiscrepancyType.MISSING_IN_LOCAL
            ]
            missing_in_psp = [
                r for r in self.report.unmatched_records 
                if r.reason == DiscrepancyType.MISSING_IN_PSP
            ]
            
            if missing_in_local:
                lines.append(f"\nMissing in Local Database ({len(missing_in_local)}):")
                for r in missing_in_local:
                    lines.append(
                        f"  PSP ID: {r.transaction_id}, "
                        f"Amount: {r.amount} {r.currency}, "
                        f"Status: {r.status}"
                    )
            
            if missing_in_psp:
                lines.append(f"\nMissing in PSP ({len(missing_in_psp)}):")
                for r in missing_in_psp:
                    lines.append(
                        f"  Local ID: {r.transaction_id}, "
                        f"Amount: {r.amount} {r.currency}, "
                        f"Status: {r.status}"
                    )
            
            lines.append("")
        
        # Discrepancy records
        if self.report.discrepancy_records:
            lines.extend([
                "DISCREPANCY RECORDS",
                "-" * 40,
            ])
            
            for r in self.report.discrepancy_records:
                lines.extend([
                    f"\nLocal ID: {r.local_id} | PSP ID: {r.psp_id}",
                    f"  Type: {r.discrepancy_type.value}",
                    f"  Field: {r.field_name}",
                    f"  Local Value: {r.local_value}",
                    f"  PSP Value: {r.psp_value}",
                ])
            
            lines.append("")
        
        # Matched records (if any)
        if self.report.matched_records:
            lines.extend([
                "MATCHED RECORDS",
                "-" * 40,
                f"Total: {len(self.report.matched_records)} matched transactions",
                "",
            ])
        
        return "\n".join(lines)
