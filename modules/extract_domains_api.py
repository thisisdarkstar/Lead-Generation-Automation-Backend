#!/usr/bin/env python3
"""
extract_domains_api

Module for fetching domain allocation data from the Namekart dashboard API
and extracting unique domain names (from both 'domainName' and 'presentDomain.domain' fields).

Usage (Command Line):
    python extract_domains_api.py -t <bearer_token> [-o output.txt] [-s <size>]

Arguments:
    -t, --token    Bearer API access token (REQUIRED).
    -o, --output   Output text filename (default: domains.txt).
    -s, --size     Number of records to fetch per API request (default: 200).

Features:
    - Graceful error handling for HTTP and network errors, KeyboardInterrupt, and file I/O issues.
    - Can be used as a CLI tool OR as an importable Python module in other scripts or APIs.

Functions:
    fetch_domains(token, size): Gets API data as JSON.
    extract_unique_domains(data): Parses domain names.
    save_domains(domains, filename): Writes domains to a file, one per line.

Example (as a module):
    from extract_domains_api import fetch_domains, extract_unique_domains, save_domains

    api_data = fetch_domains(token, size=100)
    domains = extract_unique_domains(api_data)
    save_domains(domains, 'out.txt')
"""

import requests
import json
import sys


def fetch_domains(token, size=200):
    """
    Fetches domain data from Namekart dashboard API using Bearer token.

    Args:
        token (str): Bearer API access token.
        size (int, optional): Number of records to fetch (default: 200).

    Returns:
        dict: JSON response from the API, or None if error.
    """
    url = "https://nk-dashboard-1.grayriver-ffcf7337.westus.azurecontainerapps.io/getmysocialallocations"
    params = {
        "page": "0",
        "size": str(size),
        "sort": "{}",
        "filter": "{}",
        "search": "",
    }
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "origin": "https://app.namekart.com",
        "x-auth-provider": "GOOGLE",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except KeyboardInterrupt:
        print("\nScript interrupted by user. Exiting gracefully.")
        sys.exit(0)
    except requests.RequestException as err:
        print(f"HTTP error: {err}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def extract_unique_domains(api_data):
    """
    Extracts unique domain names from API data.

    Args:
        api_data (dict): JSON response from API.

    Returns:
        list: Sorted list of unique domain names.
    """
    domains = set()
    # Extract the list from "content"
    for entry in api_data.get("content", []):
        # Get domainName if exists
        if "domainName" in entry and entry["domainName"]:
            domains.add(entry["domainName"])
        # Get nested presentDomain.domain if exists
        present_domain = entry.get("presentDomain", {}).get("domain")
        if present_domain:
            domains.add(present_domain)
    return sorted(domains)


def save_domains(domains, output_file):
    """
    Saves a list of domain names (one per line) to a text file.

    Args:
        domains (list): List of domain name strings.
        output_file (str): Output filename (path).
    """
    with open(output_file, "w", encoding="utf-8") as out:
        for domain in domains:
            out.write(domain + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract domains from dashboard API to a text file"
    )
    parser.add_argument("-t", "--token", required=True, help="Bearer API access token")
    parser.add_argument(
        "-o",
        "--output",
        default="domains.txt",
        help="Output text filename (default: domains.txt)",
    )
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=200,
        help="Number of records to fetch (default: 200)",
    )
    args = parser.parse_args()
    api_data = fetch_domains(args.token, size=args.size)
    if api_data is None:
        sys.exit(1)
    # Save API raw response for reference
    with open("domains.json", "w", encoding="utf-8") as f:
        json.dump(api_data, f, indent=2)
    print("Saved API response as domains.json.")
    # Extract and output domains only (NO header; matches OLD_STR pattern)
    domains = extract_unique_domains(api_data)
    save_domains(domains, args.output)
    print(f"Wrote {len(domains)} domains to {args.output}.")
