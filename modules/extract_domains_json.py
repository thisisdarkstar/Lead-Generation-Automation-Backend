#!/usr/bin/env python3
"""
extract_domains_json

Module for extracting domain entries and values from a JSON file, with colored output.

Features:
    - Provides functions for printing colored domain details
    - Can extract single domain, a comma-separated list, or list from a TXT file
    - Supports extracting specific key values from domain entry dicts

Usage as CLI:
    python extract_domains_json.py -i data.json -d single.domain
    python extract_domains_json.py -i data.json -l domain1,domain2
    python extract_domains_json.py -i data.json -f domains.txt
    python extract_domains_json.py -i data.json -d single.domain -k keyname

Module Functions:
    print_colored_dict(domain: str, entrylist: list[dict]) -> None
        Prints colored representation of each domain entry dict.

    load_domains_from_txt(path: str) -> list[str]
        Loads domain names from TXT file, skipping any 'Domain' header.

    process_domain(data: dict, domain: str, key: str|None = None) -> None
        Extracts domain entries (or key value) and prints colored output.

    extract_domains(data: dict, domains: list[str], key: str|None = None) -> None
        Extracts and prints colored details for multiple domains.

Example (as module):
    from extract_domains import extract_domains, process_domain

    data = ... # loaded JSON dictionary
    domains = ['ishaatech.ai', 'takomizer.ai']
    extract_domains(data, domains)
    # or for a single:
    process_domain(data, 'ishaatech.ai', key='status')
"""
import json
import sys
from colorama import Fore, Style, init

init(autoreset=True)


def print_colored_dict(domain, entrylist):
    """
    Prints colored details for all entries of a domain.

    Args:
        domain (str): Domain name.
        entrylist (list[dict]): List of entry dictionaries for this domain.
    """
    print(f"{Fore.CYAN}Domain: {domain}{Style.RESET_ALL}")
    for idx, entry in enumerate(entrylist, 1):
        print(f"{Fore.CYAN}Entry #{idx}:{Style.RESET_ALL}")
        for k, v in entry.items():
            print(
                f"{Fore.YELLOW}{k}{Style.RESET_ALL}: {Fore.GREEN}{v}{Style.RESET_ALL}"
            )
        print()


def load_domains_from_txt(path):
    """
    Loads domains from a TXT file, skipping 'Domain' header.

    Args:
        path (str): Path to TXT file.

    Returns:
        list: List of domain names.
    """
    with open(path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
        return [line for line in lines if line.lower() != "domain"]


def process_domain(data, domain, key=None):
    """
    Extracts entries for a single domain and prints colored output. Optionally extracts key value.

    Args:
        data (dict): Domain dict from loaded JSON.
        domain (str): Domain name to extract.
        key (str, optional): Key to extract from domain entries. Defaults to None (shows all).
    """
    entries = data.get(domain)
    if entries is None:
        print(f"{Fore.RED}No entries found for domain '{domain}'{Style.RESET_ALL}")
        return
    if not entries:
        print(
            f"{Fore.MAGENTA}No leads found for domain '{domain}' (empty list){Style.RESET_ALL}"
        )
        return
    if key:
        found = False
        for entry in entries:
            if key in entry:
                print(
                    f"{Fore.CYAN}{domain}{Style.RESET_ALL} | {Fore.YELLOW}{key}{Style.RESET_ALL}: {Fore.GREEN}{entry[key]}{Style.RESET_ALL}"
                )
                found = True
        if not found:
            print(
                f"{Fore.RED}No value found for key '{key}' in domain '{domain}'{Style.RESET_ALL}"
            )
    else:
        print_colored_dict(domain, entries)


def extract_domains(data, domains, key=None):
    """
    Processes multiple domains with colored output.

    Args:
        data (dict): Domain dict from loaded JSON.
        domains (list[str]): List of domain names to extract.
        key (str, optional): Key to extract from domain entries. Defaults to None.
    """
    for domain in domains:
        process_domain(data, domain, key)


# CLI entry point remains, pure logic above for flexible use
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Colored domain/key extractor for JSON."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to input JSON file")
    parser.add_argument("-d", "--domain", help="A single domain to extract")
    parser.add_argument("-l", "--list", help="Comma-separated list of domains")
    parser.add_argument("-f", "--file", help="TXT file with one domain per line")
    parser.add_argument("-k", "--key", help="Key within domain entry to extract")
    args = parser.parse_args()

    try:
        with open(args.input, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"{Fore.RED}Error loading JSON file: {e}{Style.RESET_ALL}")
        sys.exit(1)

    if args.domain:
        process_domain(data, args.domain, args.key)
        sys.exit(0)

    if args.list:
        domains = [d.strip() for d in args.list.split(",") if d.strip()]
    elif args.file:
        domains = load_domains_from_txt(args.file)
    else:
        print(
            f"{Fore.RED}Specify a domain (-d), list (-l), or file (-f).{Style.RESET_ALL}"
        )
        sys.exit(1)

    extract_domains(data, domains, args.key)
