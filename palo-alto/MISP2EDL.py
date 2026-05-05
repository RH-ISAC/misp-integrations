#!/usr/bin/env python3
"""
Retrieve last 24 hours of vetted IOCs from MISP and export them to files for Palo ALto Dynamic Lists
"""

__author__ = "Ian Furr"
__version__ = "0.1"
__email__ = "ian.furr@rhisac.org"

import requests
from datetime import datetime, timedelta
from pymisp import PyMISP
from config import misp_config as MISP_CONFIG

MISP_URL = "https://misp.rhisac.org"
VETTED_TAG = "rhisac: vetted"


def get_misp_key() -> str:
    """
    Get the MISP authkey from a local config file
    Returns
    _______
    str
        The MISP authkey
    """
    try:

        key = MISP_CONFIG["key"]
        return key
    except KeyError as e:
        print(f'Cannot find "{e}" in misp_config.')
        exit()


def get_last24h_vetted_iocs() -> list[dict]:
    """
    Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return
    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        misp = PyMISP(MISP_URL, get_misp_key())
    except Exception as e:
        print(e)
        exit()

    print(f"Getting all IOCs added to MISP in past 24 hours...")

    # Query API for IOCs
    try:
        results = misp.search("attributes", tags=[VETTED_TAG], timestamp="30d")
        iocs = results["Attribute"]
        print(f"Got {len(iocs)} IOCs from MISP")
    except Exception as e:
        print(f"Error while query MISP for IOCs: {str(e)}")
        exit()

    return iocs


def export_iocs_to_file(iocs: list[dict]) -> None:
    """
    Take a list of IOC items from MISP, and export them to files.
    Given a list of MISP IOC dicts, parse the types and then export them to individual files based on type.
    Parameters
    ----------
    iocs : list[dict]
        A list of IOCs returned from a PyMISP query (Specifically needs value, type, and timestamp fields.)
    """

    ip_list = []
    domain_list = []
    url_list = []
    other_types = set()
    for ioc in iocs:
        if ioc["type"] in ["ip-src"]:  # Could optionally add "ip-dst"
            ip_list.append(ioc)
        elif ioc["type"] in ["domain"]:
            domain_list.append(ioc)
        elif ioc["type"] in ["hostname", "url"]:
            url_list.append(ioc)
        else:
            other_types.add(ioc["type"])

    print(other_types)
    ips = "./rhisac_ip_export.txt"
    with open(ips, "a", newline="") as f_ips:
        for ioc in ip_list:
            f_ips.write(
                f"{ioc['value']} #{datetime.fromtimestamp(int(ioc['timestamp'])).strftime('%Y-%m-%d')}\n"
            )
        f_ips.close()

    domains = "./rhisac_domain_export.txt"
    with open(domains, "a", newline="") as f_domains:
        for ioc in domain_list:
            f_domains.write(
                f"*.{ioc['value']} #{datetime.fromtimestamp(int(ioc['timestamp'])).strftime('%Y-%m-%d')}\n"
            )
        f_domains.close()

    urls = "./rhisac_url_export.txt"
    with open(urls, "a", newline="") as f_urls:
        for ioc in url_list:
            f_urls.write(
                f"{ioc['value']} #{datetime.fromtimestamp(int(ioc['timestamp'])).strftime('%Y-%m-%d')}\n"
            )
        f_urls.close()
    print(f"Exported {len(ips)} IPs, {len(domains)} domains, and {len(urls)}urls.")
    return


if __name__ == "__main__":
    # Get IOCs from MISP
    iocs = get_last24h_vetted_iocs()

    if not iocs:
        print("No IOCs found in last 24h. Nothing to output.")
    else:
        export_iocs_to_file(iocs)
        print("Sent IOCs to Files. Exiting.")

    """
    Documentation
    https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/configure-the-firewall-to-access-an-external-dynamic-list
    https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/formatting-guidelines-for-an-external-dynamic-list#id65904ffb-3a09-4ceb-b476-6bae9e3ab673
    https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/formatting-guidelines-for-an-external-dynamic-list/ip-address-list#idd44a975a-a94a-4398-864e-5cf223f1d351
    https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/formatting-guidelines-for-an-external-dynamic-list/domain-list#id1e732405-4bc6-4b31-93c8-f8d82dd6a09e
    https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/formatting-guidelines-for-an-external-dynamic-list/url-list#idc3ebece1-66cb-4ca0-9864-adaea44eaf45
    """
