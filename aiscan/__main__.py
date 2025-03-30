#!/usr/bin/env python3
"""
Code Security Scanner using Local LM Studio
"""

import os
import sys
import argparse
from rich.console import Console

from .scanner.scanner import CodeScanner

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Code Security Scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format")
    parser.add_argument("--rabbit", action="store_true", help="Enable deep function analysis mode")
    parser.add_argument("--call-graph", action="store_true", help="Generate PlantUML call graphs for each file")
    parser.add_argument("--verbose", action="store_true", help="Show all LLM inputs and outputs")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        console.print(f"[red]Error: '{args.directory}' is not a valid directory.[/red]")
        sys.exit(1)

    scanner = CodeScanner(verbose=args.verbose)
    scanner.generate_call_graph = args.call_graph
    scanner.scan_directory(args.directory, csv_output=args.csv, rabbit_mode=args.rabbit)

if __name__ == "__main__":
    main() 