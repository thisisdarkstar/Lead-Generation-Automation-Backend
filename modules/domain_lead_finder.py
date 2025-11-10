#!/usr/bin/env python3
import requests
import sys
import json
import socket
from urllib.parse import urlparse
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed


def probe_dns(domain):
    """Checks if a domain resolves in DNS."""
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def is_parked(content):
    """Detect common parked/for-sale patterns in webpage content."""
    parked_patterns = [
        "buy this domain",
        "domain is for sale",
        "is parked free",
        "contact owner",
        "sedo",
        "afternic",
        "dan.com",
        "uniregistry",
        "parking",
        "parked",
        "get this domain",
        "this domain may be for sale",
    ]
    content = content.lower()
    return any(pat in content for pat in parked_patterns)


def probe_http(domain):
    """Checks if the HTTP(S) site is active and not parked or for sale."""
    parking_domains = [
        "godaddy.com",
        "sedo.com",
        "afternic.com",
        "dan.com",
        "uniregistry.com",
        "parkingcrew.net",
        "parkingpanel.com",
        "trafficz.com",
        "dynadot.com",
        "domainsherpa.com",
        "secureserver.net",
    ]
    parking_paths = [
        "/lander",
        "/parkingpage",
        "/parked",
        "/forsale",
        "/default.aspx",
        "/domain-for-sale",
    ]
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        session = requests.Session()
        for proto in ["http", "https"]:
            try:
                resp = session.get(
                    f"{proto}://{domain}",
                    timeout=6,
                    headers=headers,
                    allow_redirects=True,
                )
                if resp.status_code >= 400:
                    continue
                urls_to_check = [r.url.lower() for r in resp.history] + [
                    resp.url.lower()
                ]
                for url in urls_to_check:
                    parsed = urlparse(url)
                    netloc = parsed.netloc
                    path = parsed.path.lower()
                    query = parsed.query.lower()
                    if any(pd in netloc for pd in parking_domains):
                        return False
                    if any(pp in path for pp in parking_paths):
                        return False
                    if any(pp in query for pp in parking_paths):
                        return False
                final_domain = urlparse(resp.url).netloc.lower()
                if final_domain != domain.lower() and any(
                    pd in final_domain for pd in parking_domains
                ):
                    return False
                if len(resp.text.strip()) < 500:
                    return False
                if is_parked(resp.text):
                    return False
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def search_single(domain, probe=False):
    sld = domain.split(".")[0]
    boundary = "----WebKitFormBoundaryO2RVLFMBpaR9aeaZ"
    boundary_header = boundary[2:]
    # Use "exact" rather than "contains", and "keyword" param
    body = (
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="match_type"\r\n\r\nexact\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="keyword"\r\n\r\n{sld}\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="a"\r\n\r\nsearch\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="format"\r\n\r\njson\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="format_type"\r\n\r\nresults\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="offset"\r\n\r\n0\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="sort"\r\n\r\nextensions_taken\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="sort_dir"\r\n\r\ndesc\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="exclude_keyword"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="min_length"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="max_length"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="developed"\r\n\r\n1\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="keyword_bulk"\r\n\r\n\r\n'
        f"--{boundary_header}--\r\n"
    )
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": f"multipart/form-data; boundary={boundary_header}",
        "origin": "https://domainleads.com",
        "referer": "https://domainleads.com/index",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
        ),
    }
    response = requests.post(
        "https://domainleads.com/index", headers=headers, data=body
    )
    response.raise_for_status()
    result_json = response.json()
    return extract_domains(result_json, [sld], [domain], probe=probe)


def get_domain_extensions_from_list(domains, probe=False):
    """Accepts a list of domains (not a filename!)."""
    input_slds = [d.split(".")[0] for d in domains]
    bulk_domains = "\r\n".join(domains)
    boundary = "----WebKitFormBoundaryBSxt3zVkoUshvglL"
    boundary_header = boundary[2:]
    body = (
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="match_type"\r\n\r\ncontains\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="keyword"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="a"\r\n\r\nsearch\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="format"\r\n\r\njson\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="format_type"\r\n\r\nresults\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="offset"\r\n\r\n0\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="sort"\r\n\r\nextensions_taken\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="sort_dir"\r\n\r\ndesc\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="exclude_keyword"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="min_length"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="max_length"\r\n\r\n\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="developed"\r\n\r\n1\r\n'
        f'--{boundary_header}\r\nContent-Disposition: form-data; name="keyword_bulk"\r\n\r\n{bulk_domains}\r\n'
        f"--{boundary_header}--\r\n"
    )
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": f"multipart/form-data; boundary={boundary_header}",
        "origin": "https://domainleads.com",
        "referer": "https://domainleads.com/index",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
        ),
    }
    response = requests.post(
        "https://domainleads.com/index", headers=headers, data=body
    )
    response.raise_for_status()
    result_json = response.json()
    return extract_domains(result_json, input_slds, domains, probe=probe)


def _probe_worker(dom, url):
    try:
        if probe_dns(dom) and probe_http(dom):
            return {"domain": dom, "url": url}
    except Exception as e:
        print(colored(f"Warning: Error probing {dom}: {e}", "red"))
    return None


def extract_domains(result_json, input_slds, input_domains, probe=False):
    data = result_json["results"]["data"]
    sld_to_ext = {d["sld"]: d.get("extensions_list_dev", "") for d in data}
    output = {}
    for sld, input_domain in zip(input_slds, input_domains):
        tld_in_input = input_domain.split(".")[-1].lower()
        domain_arr = []
        ext_str = sld_to_ext.get(sld, "")
        if not ext_str:
            output[input_domain] = domain_arr
            continue

        extensions = [x.strip().lower() for x in ext_str.split(",") if x.strip()]
        probe_jobs = []
        for ext in extensions:
            if ext != tld_in_input:
                dom = f"{sld}.{ext}"
                url = f"https://{dom}"
                if probe:
                    probe_jobs.append((dom, url))
                else:
                    domain_arr.append({"domain": dom, "url": url})

        # Only probe if requested, in parallel
        if probe and probe_jobs:
            with ThreadPoolExecutor(
                max_workers=round(min(32, len(probe_jobs)))
            ) as executor:
                futures = {
                    executor.submit(_probe_worker, dom, url): (dom, url)
                    for dom, url in probe_jobs
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        domain_arr.append(result)
        output[input_domain] = domain_arr
    return output


def print_colored_json(obj, indent=0):
    """Prints a Python dict/list as colorized JSON-like text in the terminal."""
    space = "  " * indent
    if isinstance(obj, dict):
        print(colored("{", "white"))
        for i, (k, v) in enumerate(obj.items()):
            end = "," if i < len(obj) - 1 else ""
            print(
                space + "  " + colored(f'"{k}"', "yellow") + colored(": ", "white"),
                end="",
            )
            print_colored_json(v, indent + 1)
            if end:
                print(colored(end, "white"))
        print(space + colored("}", "white"), end="")
    elif isinstance(obj, list):
        print(colored("[", "white"))
        for i, item in enumerate(obj):
            end = "," if i < len(obj) - 1 else ""
            print(space + "  ", end="")
            print_colored_json(item, indent + 1)
            if end:
                print(colored(end, "white"))
        print(space + colored("]", "white"), end="")
    elif isinstance(obj, str):
        print(colored(f'"{obj}"', "green"), end="")
    elif isinstance(obj, (int, float)):
        print(colored(str(obj), "cyan"), end="")
    elif obj is None:
        print(colored("null", "magenta"), end="")
    elif isinstance(obj, bool):
        print(colored(str(obj).lower(), "magenta"), end="")
    else:
        print(colored(repr(obj), "red"), end="")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DomainLeadFinder: Find alternate TLDs, optionally probe for live URLs."
    )
    parser.add_argument("-d", help="Single domain (e.g. apex.com)")
    parser.add_argument("-f", dest="file", help="File of domains, one per line")
    parser.add_argument("--output", help="Results file (JSON)")
    parser.add_argument(
        "-p",
        "--probe",
        action="store_true",
        help="Only return domains confirmed live and non-parked via DNS+HTTP probe",
    )
    args = parser.parse_args()

    domains = []
    if args.d:
        domains.append(args.d)
    if args.file:
        try:
            with open(args.file) as f:
                domains += [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(colored(f"Error reading domain list: {e}", "red"))
            sys.exit(2)
    if not domains:
        parser.print_help()
        sys.exit(1)

    try:
        if len(domains) == 1:
            results = search_single(domains[0], probe=args.probe)
        else:
            results = get_domain_extensions_from_list(domains, probe=args.probe)
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(results, fh, indent=2)
            print(colored(f"Results saved to {args.output}", "green"))
        else:
            print_colored_json(results)
            print()
    except KeyboardInterrupt:
        print(colored("\nAborted by user (KeyboardInterrupt).", "magenta"))
        sys.exit(130)
    except Exception as exc:
        print(colored(f"Fatal error: {exc}", "red"))
        sys.exit(5)
