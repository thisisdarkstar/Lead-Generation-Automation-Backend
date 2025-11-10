#!/usr/bin/env python3
import requests
import sys
import json


def search_single(domain):
    sld = domain.split(".")[0]
    tld_in_input = domain.split(".")[-1].lower()
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
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    }
    response = requests.post(
        "https://domainleads.com/index", headers=headers, data=body
    )
    response.raise_for_status()
    result_json = response.json()
    return extract_domains(result_json, [sld], [domain])


def get_domain_extensions_from_list(domains):
    """
    Accepts a list of domains (not a filename!).
    Returns the same result format as bulk file mode.
    """
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
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    }
    response = requests.post(
        "https://domainleads.com/index", headers=headers, data=body
    )
    response.raise_for_status()
    result_json = response.json()
    return extract_domains(result_json, input_slds, domains)


def extract_domains(result_json, input_slds, input_domains):
    # Same object array format, both modes
    data = result_json["results"]["data"]
    sld_to_ext = {d["sld"]: d.get("extensions_list_dev", "") for d in data}
    output = {}
    for sld, input_domain in zip(input_slds, input_domains):
        tld_in_input = input_domain.split(".")[-1].lower()
        domain_arr = []
        ext_str = sld_to_ext.get(sld, "")
        if ext_str:
            extensions = [x.strip().lower() for x in ext_str.split(",") if x.strip()]
            for ext in extensions:
                if ext != tld_in_input:
                    dom = f"{sld}.{ext}"
                    url = f"https://{dom}"
                    domain_arr.append({"domain": dom, "url": url})
        output[input_domain] = domain_arr
    return output


def parse_cli():
    # New pattern: -d/--domain for single search; -f/--file/-l/--list for bulk
    domains_file = None
    output_file = None
    single_domain = None
    for i, arg in enumerate(sys.argv):
        if arg in ["-l", "--list", "-f", "--file"] and i + 1 < len(sys.argv):
            domains_file = sys.argv[i + 1]
        if arg in ["-o", "--output"] and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
        if arg in ["-d", "--domain"] and i + 1 < len(sys.argv):
            single_domain = sys.argv[i + 1]
    return domains_file, single_domain, output_file


from termcolor import colored


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


# Example use in your main:
if __name__ == "__main__":
    domains_file, single_domain, output_file = parse_cli()
    if not domains_file and not single_domain:
        print(
            "Usage: python script.py [-d | --domain] example.com | [-l | --list | -f | --file] domains.txt [-o | --output] output.json"
        )
        sys.exit(1)
    if single_domain:
        result = search_single(single_domain)
    else:
        result = get_domain_extensions_from_file(domains_file)
    if output_file:
        with open(output_file, "w") as outf:
            json.dump(result, outf, indent=2)
        print(f"Results written to {output_file}")
    else:
        print_colored_json(result)
        print()  # for final newline
