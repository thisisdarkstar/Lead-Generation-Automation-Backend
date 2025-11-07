#!/usr/bin/env python3
"""
extract_domains_html

Module for extracting domain names from HTML files containing:
- <div class="MuiStack-root ..."><p class="MuiTypography-body2 ...">domain</p></div>

Usage (CLI):
    python extract_domains_from_html.py -i input.html -o output.txt

Arguments:
    -i, --input     Path to input HTML file (REQUIRED)
    -o, --output    Path to output TXT file (REQUIRED)

Features:
    - Extracts only domain strings found in matching nested tags
    - Deduplicates and sorts domains before saving
    - No header in output
    - Success message on completion

Module Functions:
    extract_domains_from_html(input_file: str) -> list[str]
        Parses input HTML file and returns sorted, unique domains.

    save_domains(domains: list[str], output_file: str) -> None
        Saves domains as lines to output file.

Example (as module):
    from extract_domains_from_html import extract_domains_from_html, save_domains

    domains = extract_domains_from_html("table.html")
    save_domains(domains, "domains.txt")
"""

import re
from bs4 import BeautifulSoup


def extract_domains_from_html(input_file):
    """
    Extract domain names from target <div>/<p> structure in an HTML file.

    Args:
        input_file (str): Path to input HTML file.

    Returns:
        list: Sorted list of unique domain names.
    """
    # Domain regex pattern (matches domains with a dot)
    domain_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    domains = []

    with open(input_file, "r", encoding="utf-8") as f:
        html = f.read()

    soup = BeautifulSoup(html, "html.parser")

    # Find <div> elements with MuiStack-root, then nested <p> with MuiTypography-body2
    for div in soup.find_all("div", class_=re.compile("MuiStack-root")):
        for p in div.find_all("p", class_=re.compile("MuiTypography-body2")):
            text = p.get_text(strip=True)
            # Only add if matches domain pattern
            if re.match(domain_pattern, text):
                domains.append(text)

    # Deduplicate and sort domains
    return sorted(set(domains))


def save_domains(domains, output_file):
    """
    Writes the list of domains to output file, one per line.

    Args:
        domains (list): List of domain strings.
        output_file (str): Path to output file.
    """
    with open(output_file, "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(f"{domain}\n")
    print("Extraction completed successfully.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract domain names from <p> under <div class='MuiStack-root'>."
    )
    parser.add_argument("-i", "--input", required=True, help="Input HTML file")
    parser.add_argument("-o", "--output", required=True, help="Output TXT file")
    args = parser.parse_args()
    domains = extract_domains_from_html(args.input)
    save_domains(domains, args.output)
