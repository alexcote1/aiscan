import csv
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def display_results(results: List[Dict[str, Any]], csv_output: bool = False, rabbit_mode: bool = False):
    """Display the analysis results in a formatted table or CSV."""
    if csv_output:
        _display_csv(results, rabbit_mode)
        return

    # First, collect and display entry points
    entry_points = []
    for result in results:
        if "error" not in result:
            for finding in result["findings"]:
                if finding.get("is_entry_point"):
                    entry_points.append({
                        "file": result["file"],
                        "function": finding.get("function_name", ""),
                        "line": finding.get("start_line", ""),
                        "severity": finding.get("severity", ""),
                        "confidence": finding.get("confidence", ""),
                        "analysis": finding.get("function_analysis", {}) if rabbit_mode else {},
                        "called_functions": finding.get("called_functions", [])
                    })

    if entry_points:
        console.print("\n[bold blue]Detected Entry Points:[/bold blue]")
        entry_table = Table(show_header=True, header_style="bold magenta", box=None)
        entry_table.add_column("File", style="cyan", no_wrap=True)
        entry_table.add_column("Function", style="cyan", no_wrap=True)
        entry_table.add_column("Line", style="blue", justify="right")
        entry_table.add_column("Called Functions", style="cyan", no_wrap=True)
        entry_table.add_column("Severity", style="red", no_wrap=True)
        entry_table.add_column("Confidence", style="blue", no_wrap=True)
        
        if rabbit_mode:
            entry_table.add_column("Summary", style="white", overflow="fold")
        
        for entry in sorted(entry_points, key=lambda x: (x["file"], x["function"])):
            # Color-code severity
            severity_color = {
                "High": "red",
                "Medium": "yellow",
                "Low": "green"
            }.get(entry["severity"], "white")
            
            # Color-code confidence
            confidence_color = {
                "High": "green",
                "Medium": "yellow",
                "Low": "red"
            }.get(entry["confidence"], "white")
            
            row = [
                entry["file"],
                entry["function"],
                str(entry["line"]),
                ", ".join(entry["called_functions"]),
                f"[{severity_color}]{entry['severity']}[/{severity_color}]",
                f"[{confidence_color}]{entry['confidence']}[/{confidence_color}]"
            ]
            
            if rabbit_mode:
                row.append(entry["analysis"].get("function_summary", ""))
            
            entry_table.add_row(*row)
        
        console.print(entry_table)
        console.print("\n[bold]Security Analysis Results:[/bold]")
    else:
        console.print("\n[bold]No entry points detected.[/bold]")
        console.print("\n[bold]Security Analysis Results:[/bold]")

    # Now display the security findings
    table = Table(show_header=True, header_style="bold magenta", box=None)
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Function", style="cyan", no_wrap=True)
    table.add_column("Called Functions", style="cyan", no_wrap=True)
    table.add_column("Finding", style="yellow", no_wrap=True)
    table.add_column("Severity", style="red", no_wrap=True)
    table.add_column("Confidence", style="blue", no_wrap=True)
    table.add_column("Description", style="white", overflow="fold")
    table.add_column("Evidence", style="white", overflow="fold")
    table.add_column("Impact", style="white", overflow="fold")
    table.add_column("Fix", style="green", overflow="fold")
    
    if rabbit_mode:
        table.add_column("Function Analysis", style="white", overflow="fold")

    # Group findings by severity
    findings_by_severity = {
        "High": [],
        "Medium": [],
        "Low": []
    }

    for result in results:
        if "error" not in result:
            for finding in result["findings"]:
                # Normalize severity to title case
                severity = finding.get("severity", "Low").title()
                if severity not in findings_by_severity:
                    severity = "Low"  # Default to Low if unknown severity
                findings_by_severity[severity].append((result["file"], finding))

    # Display findings by severity
    for severity in ["High", "Medium", "Low"]:
        if findings_by_severity[severity]:
            console.print(f"\n[bold {severity.lower()}]High Severity Findings:[/bold {severity.lower()}]" if severity == "High" else
                         f"\n[bold {severity.lower()}]Medium Severity Findings:[/bold {severity.lower()}]" if severity == "Medium" else
                         f"\n[bold {severity.lower()}]Low Severity Findings:[/bold {severity.lower()}]")
            
            for file_path, finding in sorted(findings_by_severity[severity], key=lambda x: (x[0], x[1].get("function_name", ""))):
                # Color-code confidence levels
                confidence_color = {
                    "High": "green",
                    "Medium": "yellow",
                    "Low": "red"
                }.get(finding["confidence"], "white")
                
                # Color-code severity levels
                severity_color = {
                    "High": "red",
                    "Medium": "yellow",
                    "Low": "green"
                }.get(finding["severity"], "white")
                
                function_name = finding.get("function_name", "")
                called_functions = ", ".join(finding.get("called_functions", []))
                
                # Add import information if available
                if finding.get("imported_from"):
                    function_name = f"{function_name} (from {finding['imported_from']})"
                
                row = [
                    file_path,
                    function_name,
                    called_functions,
                    finding["title"],
                    f"[{severity_color}]{finding['severity']}[/{severity_color}]",
                    f"[{confidence_color}]{finding['confidence']}[/{confidence_color}]",
                    finding["description"],
                    finding["evidence"],
                    finding["impact"],
                    finding["fix"]
                ]
                
                if rabbit_mode:
                    analysis = finding.get("function_analysis", {})
                    analysis_text = f"Summary: {analysis.get('function_summary', '')}\n"
                    analysis_text += f"Vulnerabilities: {analysis.get('potential_vulnerabilities', '')}\n"
                    analysis_text += f"Logic Flaws: {analysis.get('logic_flaws', '')}\n"
                    analysis_text += f"Data Flow: {analysis.get('data_flow', '')}"
                    row.append(analysis_text)
                
                table.add_row(*row)

    console.print(table)

    # Display analysis errors if any
    all_errors = []
    for result in results:
        if "error" in result:
            all_errors.append(result["error"])
        if "analysis_errors" in result:
            all_errors.extend(result["analysis_errors"])

    if all_errors:
        console.print("\n[bold red]Analysis Errors:[/bold red]")
        for error in all_errors:
            console.print(f"[red]• {error}[/red]")

def _display_csv(results: List[Dict[str, Any]], rabbit_mode: bool = False):
    """Display results in CSV format."""
    # Write to CSV file
    with open("security_scan_results.csv", "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        headers = ["File", "Function", "Called Functions", "Finding", "Severity", "Confidence", "Description", "Evidence", "Impact", "Fix"]
        if rabbit_mode:
            headers.extend(["Function Summary", "Potential Vulnerabilities", "Logic Flaws", "Data Flow"])
        writer.writerow(headers)
        
        for result in results:
            # Handle special result types
            if "errors" in result:
                # This is an analysis errors result
                for error in result["errors"]:
                    row = [result["file"], "", "", "Analysis Error", "", "", error, "", "", ""]
                    if rabbit_mode:
                        row.extend(["", "", "", ""])
                    writer.writerow(row)
                continue
                
            if "orphaned_functions" in result:
                # This is an orphaned functions result
                for func in result["orphaned_functions"]:
                    row = [
                        func["file"],
                        func["name"],
                        "",
                        "Orphaned Function",
                        "Low",
                        "High",
                        f"Function '{func['name']}' is not called by any entry point",
                        f"Located in {func['file']} at lines {func['start_line']}-{func['end_line']}",
                        "May indicate dead code or incomplete implementation",
                        "Review function usage and consider removal if unused"
                    ]
                    if rabbit_mode:
                        row.extend(["", "", "", ""])
                    writer.writerow(row)
                continue
            
            # Handle regular findings
            if "error" in result:
                row = [result["file"], "", "", "Error", "", "", result["error"], "", "", ""]
                if rabbit_mode:
                    row.extend(["", "", "", ""])
                writer.writerow(row)
            else:
                for finding in result["findings"]:
                    # Clean up the values to ensure they're CSV-safe
                    function_name = finding.get("function_name", "")
                    called_functions = "; ".join(finding.get("called_functions", []))
                    row = [
                        result["file"],
                        function_name,
                        called_functions,
                        finding["title"].replace("\n", " ").replace(",", ";"),
                        finding["severity"].replace("\n", " ").replace(",", ";"),
                        finding["confidence"].replace("\n", " ").replace(",", ";"),
                        finding["description"].replace("\n", " ").replace(",", ";"),
                        finding["evidence"].replace("\n", " ").replace(",", ";"),
                        finding["impact"].replace("\n", " ").replace(",", ";"),
                        finding["fix"].replace("\n", " ").replace(",", ";")
                    ]
                    
                    if rabbit_mode:
                        analysis = finding.get("function_analysis", {})
                        row.extend([
                            analysis.get("function_summary", "").replace("\n", " ").replace(",", ";"),
                            analysis.get("potential_vulnerabilities", "").replace("\n", " ").replace(",", ";"),
                            analysis.get("logic_flaws", "").replace("\n", " ").replace(",", ";"),
                            analysis.get("data_flow", "").replace("\n", " ").replace(",", ";")
                        ])
                    
                    writer.writerow(row)
    
    console.print("\n[green]Results have been saved to security_scan_results.csv[/green]") 