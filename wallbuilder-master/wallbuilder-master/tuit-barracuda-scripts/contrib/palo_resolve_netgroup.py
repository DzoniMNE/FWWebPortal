#!/usr/bin/env python3
import argparse
import ipaddress
from typing import Any, Dict, List, Optional, Union
import urllib.parse
from urllib.parse import urljoin
import requests
import yaml


RESTAPI_VERSION_ENC = "v10.0"

IPAddressOrNetwork = Union[
    ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network,
    str
]


def quote_plus(s: str) -> str:
    return urllib.parse.quote_plus(s, safe="")


def rest_get(config: Dict[str, Any], path: str):
    earl = urljoin(f"{config['firewall']['base_uri']}/restapi/{RESTAPI_VERSION_ENC}/", path)
    response = requests.get(
        earl,
        headers={
            "Accept": "application/json",
            "X-PAN-KEY": config["firewall"]["api_key"],
        },
        verify=False,
    )
    if response.status_code != 200:
        response.raise_for_status()
    return response.json()


def get_addr_groups_for_dev_group(config: Dict[str, Any], dev_group: Optional[str]) -> Dict[str, List[str]]:
    if dev_group is not None:
        path = f"Objects/AddressGroups?location=device-group&device-group={quote_plus(dev_group)}"
    else:
        path = "Objects/AddressGroups?location=shared"

    addr_groups_json = rest_get(config, path)

    results = {}
    for entry in addr_groups_json["result"]["entry"]:
        if "dynamic" in entry:
            continue

        key = entry["@name"]
        try:
            value = entry["static"]["member"]
        except KeyError:
            print(entry)
            continue
        results[key] = value

    return results


def get_addrs_for_dev_group(config: Dict[str, Any], dev_group: Optional[str]) -> Dict[str, IPAddressOrNetwork]:
    if dev_group is not None:
        path = f"Objects/Addresses?location=device-group&device-group={quote_plus(dev_group)}"
    else:
        path = "Objects/Addresses?location=shared"

    addrs_json = rest_get(config, path)

    results = {}
    for entry in addrs_json["result"]["entry"]:
        key = entry["@name"]
        try:
            if "/" in entry["ip-netmask"]:
                value = ipaddress.ip_network(entry["ip-netmask"])
            else:
                value = ipaddress.ip_address(entry["ip-netmask"])
        except KeyError:
            try:
                value = entry["fqdn"]
            except KeyError:
                print(entry)
                continue

        results[key] = value

    return results


def resolve_group(name: str, addr_groups: Dict[str, List[str]], addrs: Dict[str, IPAddressOrNetwork]) -> List[IPAddressOrNetwork]:
    addr = addrs.get(name, None)
    if addr is not None:
        return [addr]

    # throws KeyError for us if it doesn't exist
    addr_group = addr_groups[name]
    result = []
    for group_member in addr_group:
        # recursion!
        result.extend(resolve_group(group_member, addr_groups, addrs))
    return result


def net_sort_key(net: IPAddressOrNetwork):
    if hasattr(net, "prefixlen"):
        return (0, net.version, net.network_address, 0, net.prefixlen)
    elif hasattr(net, "exploded"):
        return (0, net.version, net, 1)
    else:
        # assume hostname
        return (1, net)


def main():
    parser = argparse.ArgumentParser(
        description="Attempts to resolve the actual addresses behind an address group.",
    )
    parser.add_argument(
        "-c", "--config",
        dest="config", type=argparse.FileType("rb"), default=None,
        help="The configuration file to open.",
    )
    parser.add_argument(
        "-g", "--device-group",
        dest="dev_groups", action="append", default=[],
        help="Add a device group into consideration when resolving references. Objects of the same name in later device groups overwrite earlier ones.",
    )
    parser.add_argument(
        dest="addr_groups", nargs="+", metavar="ADDRGROUP",
        help="An address group to attempt to resolve.",
    )
    args = parser.parse_args()

    if args.config is None:
        args.config = open("config.yaml", "rb")
    with args.config:
        config = yaml.safe_load(args.config)

    # shared address groups first, then in command line order
    # same order for addresses
    addr_groups: Dict[str, List[str]] = get_addr_groups_for_dev_group(config, None)
    addrs: Dict[str, IPAddressOrNetwork] = get_addrs_for_dev_group(config, None)
    for dev_group in args.dev_groups:
        addr_groups.update(get_addr_groups_for_dev_group(config, dev_group))
        addrs.update(get_addrs_for_dev_group(config, dev_group))

    # resolve it all
    for addr_group in args.addr_groups:
        resolved = resolve_group(addr_group, addr_groups, addrs)
        resolved.sort(key=net_sort_key)
        print(addr_group, [str(addr) for addr in resolved])


if __name__ == "__main__":
    main()
