#!/usr/bin/env python3
"""
extract_domains_csv

Module for extracting unique domain names from a CSV file with a "domain" column.
Writes the domains (one per line, sorted, no duplicates) into an output text file.

Usage as CLI:
    python extract_domains_csv.py -f input.csv [-o output.txt]

Arguments:
    -f, --file      Path to input CSV file (REQUIRED)
    -o, --output    Output text filename (default: domains.txt)

Features:
    - Graceful error handling for file/IO issues and KeyboardInterrupt
    - Skips header row automatically (with DictReader)
    - No duplicate domains in output
    - Output file is sorted alphabetically

Module Functions:
    get_domains_from_csv(csv_file) -> set[str]:
        Returns a set of unique domains from the given CSV file's "domain" column.

    save_domains(domains, output_file):
        Saves a set or list of domains to a text file, one per line, sorted.

    extract_domains(input_csv, output_txt):
        Runs the full extraction+write pipeline (for CLI entry or batch scripting).

Example (as module):
    from extract_domains_csv import get_domains_from_csv, save_domains

    domains = get_domains_from_csv("domains.csv")
    save_domains(domains, "domains.txt")
"""

import csv
import sys


def get_domains_from_csv(csv_file):
    """
    Reads a CSV file and returns a set of unique domains from the "domain" column.

    Args:
        csv_file (str): Path to the input CSV file.

    Returns:
        set: Unique domain names found in "domain" column.
    """
    domains = set()
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain")
                if domain:
                    domains.add(domain)
    except KeyboardInterrupt:
        print("\nInterrupted while reading file. Exiting gracefully.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"File not found: {csv_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(2)
    return domains


def save_domains(domains, output_file):
    """
    Writes a set or list of domains to a text file, one per line, sorted alphabetically.

    Args:
        domains (iterable): Collection of domain strings.
        output_file (str): Path to output text file.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as out:
            for domain in sorted(domains):
                out.write(domain + "\n")
        print(f"{len(domains)} domains written to {output_file}!")
    except KeyboardInterrupt:
        print("\nInterrupted during writing. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(3)


def extract_domains(input_file, output_file):
    """
    Complete pipeline: extracts domains from CSV and writes to output.

    Args:
        input_file (str): Path to input CSV.
        output_file (str): Path to output TXT file.
    """
    domains = get_domains_from_csv(input_file)
    save_domains(domains, output_file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract domains from a CSV to a domains text file"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to input CSV file")
    parser.add_argument(
        "-o",
        "--output",
        default="domains.txt",
        help="Output text filename (default: domains.txt)",
    )
    args = parser.parse_args()
    try:
        extract_domains(args.file, args.output)
    except KeyboardInterrupt:
        print("\nScript interrupted by user. Exiting gracefully.")
        sys.exit(0)
