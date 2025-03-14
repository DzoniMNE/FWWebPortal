"""
# tuitfw.fw.paloalto

Communicates with a Palo Alto firewall or Panorama appliance via the REST API to obtain and/or
modify rules.

## Configuration

The following configuration stanzas are recognized in the `firewall` section if `type` is set to
`paloalto`:

* `base_uri` is the base URI of the Palo Alto REST API endpoint to contact. The paths to the
  respective endpoints are constructed relative to this base URI.
* `api_key` is the API key with which to authenticate against the REST API endpoint.
* `addr_groups` defines which address groups are modified and how. It is documented later in this
  section.

#### addr_groups subsection

The `addr_groups` subsection defines which address groups are modified and how.

* `location` is the location at which the network object should be modified. It is one of the
  following:
  * `shared`
  * `device-group`
* type-specific options:
  * `device_group`, the name of the device group.
* `name_format_ipv4` is a Python format string (`str.format`) to transform a database network
  object name (as listed in `common.allowed_object_names`) to the name of the firewall address
  group to be populated with IPv4 addresses. The database network object name is passed as
  positional argument 0. For example, `"NETDBV4-{0}"` transforms `ALL` into `NETDBV4-ALL`.
* `name_format_ipv6` is the IPv6 counterpart to `name_format_ipv4`.
* `addr_prefix_ipv4` is the prefix to be given to IPv4 address objects administered by this script.
* `addr_prefix_ipv6` is the prefix to be given to IPv6 address objects administered by this script.
* `push_device_group` is the device group to which the committed updates should be pushed if the API
  target is a Panorama box. Don't specify it (or set it to `null`) if you are communicating directly
  with a firewall.
* `sentinel_ipv4` is the name of the address object used to ensure that an IPv4 address group is
  never empty.
* `sentinel_ipv6` is the name of the address object used to ensure that an IPv6 address group is
  never empty.

The following table illustrates which type-specific options are required with which types:

| `location`     | `device_group` |
| -------------- | -------------- |
| `shared`       |                |
| `device-group` | required       |
"""

from collections import defaultdict
import ipaddress
import json
from time import sleep
from typing import AbstractSet, Any, DefaultDict, Dict, List, Mapping, Optional, Set, Tuple
from typing import Union
import urllib.parse
from xml.etree.ElementTree import Element
from defusedxml.ElementTree import fromstring as defused_from_string, tostring as defused_to_string
import requests
from . import FirewallSession
from .. import loggage
from ..common import AnyIPNetwork, FirewallDiff, NetworkObjectEntry, raise_config_missing_key


RESTAPI_VERSION_ENC = "v10.0"
LOCATION_TO_ALL_ADDRESSES_ENDPOINT_PATH_FORMAT = {
    "shared": "restapi/{version}/Objects/Addresses?location=shared",
    "device-group": "restapi/{version}/Objects/Addresses?location=device-group&device-group={device_group}",
}
LOCATION_TO_ADDRESS_ENDPOINT_PATH_FORMAT = {
    "shared": "restapi/{version}/Objects/Addresses?location=shared&name={name}",
    "device-group": "restapi/{version}/Objects/Addresses?location=device-group&device-group={device_group}&name={name}",
}
LOCATION_TO_ADDRESS_GROUP_ENDPOINT_PATH_FORMAT = {
    "shared": "restapi/{version}/Objects/AddressGroups?location=shared&name={name}",
    "device-group": "restapi/{version}/Objects/AddressGroups?location=device-group&device-group={device_group}&name={name}",
}
COMMIT_PATH_FORMAT = "api/?type=commit&action=partial&cmd={xml}"
COMMIT_XML_FORMAT = "<commit><partial><admin><member>{username}</member></admin></partial></commit>"
PUSH_PATH_FORMAT = "api/?type=commit&action=all&cmd={xml}"
PUSH_XML_FORMAT = "<commit-all><shared-policy><device-group><entry name=\"{device_group}\" /></device-group></shared-policy></commit-all>"
JOB_STATE_PATH_FORMAT = "api/?type=op&cmd={xml}"
JOB_STATE_XML_FORMAT = "<show><jobs><id>{job_no}</id></jobs></show>"
OBJECT_STILL_REFERENCED_CODE = 9


class AddressGroupMetadata:
    """Metadata of a firewall address group."""

    def __init__(self, exists: bool, description: str, ip_ver: int):
        self.exists: bool = exists
        self.description: str = description
        self.ip_ver: int = ip_ver

    def __repr__(self) -> str:
        return f"AddressGroupMetadata(exists={self.exists!r}, description={self.description!r}, ip_ver={self.ip_ver!r})"


def _firewall_request(
    firewall_config: Mapping[str, Any],
    location_to_path_format: Mapping[str, str],
    more_opts: Optional[Mapping[str, str]] = None,
    method: str = "GET",
    json_body: Optional[Any] = None,
    expected_codes: Optional[AbstractSet[int]] = None,
    add_headers: Optional[Mapping[str, str]] = None,
) -> Tuple[int, Optional[Dict[str, Any]]]:

    if expected_codes is None:
        expected_codes = {200}

    try:
        base_uri: str = firewall_config['base_uri']
        api_key: str = firewall_config['api_key']
        ca_cert_location: Union[str, bool] = firewall_config.get('ca_cert_location', False)
        addr_groups_config: Dict[str, Any] = firewall_config['addr_groups']
    except KeyError as ex:
        raise_config_missing_key(f"firewall.{ex.args[0]}")

    try:
        location: str = addr_groups_config['location']
    except KeyError as ex:
        raise_config_missing_key(f"firewall.addr_groups.{ex.args[0]}")

    opts_dict: Dict[str, str] = {
        urllib.parse.quote(k, safe=''): urllib.parse.quote_plus(v)
        for (k, v) in addr_groups_config.items()
    }
    opts_dict["version"] = RESTAPI_VERSION_ENC
    if more_opts is not None:
        opts_dict.update(more_opts)

    endpoint_path: str = location_to_path_format[location].format(**opts_dict)
    uri = urllib.parse.urljoin(base_uri, endpoint_path)

    headers: Dict[str, str] = dict(add_headers) if add_headers is not None else {}
    headers['Accept'] = 'application/json'
    headers['X-PAN-KEY'] = api_key

    addenda: Dict[str, Any] = {}
    if json_body is not None:
        addenda['json'] = json_body

    logger = loggage.get_logger(__name__)
    if json_body is not None:
        logger.debug(f"firewall request: {method} {uri} with body: {json.dumps(json_body)}")
    else:
        logger.debug(f"firewall request: {method} {uri}")
    response = requests.request(method, uri, headers=headers, verify=ca_cert_location, **addenda)
    if response.status_code not in expected_codes:
        # bad
        logger.critical(
            f"server responded with an error (HTTP {response.status_code}): {response.text}"
        )
        raise ValueError(f"firewall responded with unexpected error code {response.status_code}")

    return (response.status_code, response.json() if len(response.content) > 0 else None)


def _escape_xml(s: str, quot: bool = True, apos: bool = False) -> str:
    ret = []
    for c in s:
        if c == "<":
            ret.append("&lt;")
        elif c == ">":
            ret.append("&gt;")
        elif c == "&":
            ret.append("&amp;")
        elif c == '"' and quot:
            ret.append("&#34;")
        elif c == "'" and apos:
            ret.append("&#39;")
        elif ord(c) >= 0x20 and ord(c) <= 0x7E:
            ret.append(c)
        else:
            ret.append("&#{0};".format(ord(c)))
    return "".join(ret)


def _firewall_xml_request(
    config: Mapping[str, Any],
    path: str,
) -> Tuple[int, Optional[Element]]:
    firewall_config: Dict[str, Any] = config['firewall']

    try:
        base_uri: str = firewall_config['base_uri']
        api_key: str = firewall_config['api_key']
        ca_cert_location: Union[str, bool] = firewall_config.get('ca_cert_location', False)
    except KeyError as ex:
        raise_config_missing_key(f"firewall.{ex.args[0]}")

    uri = urllib.parse.urljoin(base_uri, path)

    headers: Dict[str, str] = {}
    headers['Accept'] = 'text/xml'
    headers['X-PAN-KEY'] = api_key

    method = "GET"

    logger = loggage.get_logger(__name__)
    logger.debug(f"firewall XML request: {method} {uri}")
    response = requests.request(method, uri, headers=headers, verify=ca_cert_location)
    if response.status_code != 200:
        # bad
        logger.critical(
            f"failed to obtain server data (HTTP {response.status_code}): {response.text}"
        )
        raise ValueError(f"firewall responded with unexpected error code {response.status_code}")

    return (
        response.status_code,
        defused_from_string(response.text) if response.text else None,
    )


def _wait_for_job_completion(
    config: Mapping[str, Any],
    job_no: str,
):
    logger = loggage.get_logger(__name__)

    # poll until job is done
    while True:
        job_state_xml_text = JOB_STATE_XML_FORMAT.format(
            job_no=_escape_xml(job_no),
        )
        job_state_path = JOB_STATE_PATH_FORMAT.format(
            xml=urllib.parse.quote_plus(job_state_xml_text),
        )
        _status, job_state_result = _firewall_xml_request(config, job_state_path)

        logger.debug(f"job state response: {defused_to_string(job_state_result)}")

        status_code = job_state_result.find("./result/job/status").text
        if status_code == "ACT":
            # not done yet
            sleep(5.0)
            continue

        if status_code != "FIN":
            raise ValueError("job in unknown state {status_code!r}: {defused_to_string(job_state_result)}")

        res_code = job_state_result.find("./result/job/result").text
        if res_code == "PEND":
            # not done yet
            sleep(5.0)
            continue

        if res_code == "OK":
            # done!
            break

        raise ValueError("job has unknown result {res_code!r}: {defused_to_string(job_state_result)}")


def _obtain_name_to_addr(config: Mapping[str, Any]) -> Dict[str, NetworkObjectEntry]:
    firewall_config: Dict[str, Any] = config['firewall']

    # get all addresses
    _code, j = _firewall_request(
        firewall_config,
        LOCATION_TO_ALL_ADDRESSES_ENDPOINT_PATH_FORMAT,
    )
    assert j is not None
    name_to_address: Dict[str, NetworkObjectEntry] = {
        entry["@name"]: NetworkObjectEntry(
            ip=ipaddress.ip_network(entry["ip-netmask"]),
            comment=entry.get("description", ""),
            additional_info={
                "name": entry["@name"],
            },
        )
        for entry in j['result']['entry']
        if "ip-netmask" in entry
    }
    return name_to_address


def _obtain_addr_definition(config: Mapping[str, Any], addr_name: str) -> Optional[Dict[str, Any]]:
    firewall_config: Dict[str, Any] = config['firewall']

    code, j = _firewall_request(
        firewall_config,
        LOCATION_TO_ADDRESS_ENDPOINT_PATH_FORMAT,
        {"name": addr_name},
        expected_codes={200, 404},
    )
    if code == 404:
        return None
    assert code == 200
    assert j is not None

    return j['result']['entry'][0]


def _obtain_group_definition(
    config: Mapping[str, Any],
    addr_group_name: str,
) -> Optional[Dict[str, Any]]:
    firewall_config: Dict[str, Any] = config['firewall']

    # get address group
    code, j = _firewall_request(
        firewall_config,
        LOCATION_TO_ADDRESS_GROUP_ENDPOINT_PATH_FORMAT,
        {"name": addr_group_name},
        expected_codes={200, 404},
    )
    if code == 404:
        return None
    assert code == 200
    assert j is not None

    return j['result']['entry'][0]


def _obtain_entries_for_group(
    config: Mapping[str, Any],
    addr_group_name: str,
    name_to_addr: Mapping[str, NetworkObjectEntry],
) -> List[NetworkObjectEntry]:
    logger = loggage.get_logger(__name__)

    addr_group_def = _obtain_group_definition(config, addr_group_name)

    members = addr_group_def['static']['member'] if addr_group_def is not None else []

    entries: List[NetworkObjectEntry] = []
    for member in members:
        try:
            address = name_to_addr[member]
        except KeyError as ex:
            logger.warning(
                f"address {ex.args[0]!r} referenced by address group {addr_group_name!r}"
                " not found; is it an IP-Netmask entry?"
            )

        preexisting = [
            noe
            for noe
            in entries
            if (noe.ip.network_address, noe.ip.prefixlen) == (address.ip.network_address, address.ip.prefixlen)
        ]
        if len(preexisting) > 0:
            logger.warning(
                f"duplicate entry: {address.ip.network_address}/{address.ip.prefixlen} appears"
                f" multiple times in the address group {addr_group_name!r}"
            )

        entries.append(address)

    return entries


def _sanitize_addr_name(ip_str: str) -> str:
    ret: List[str] = []
    for c in ip_str:
        if c >= "0" and c <= "9":
            ret.append(c)
        elif c >= "a" and c <= "f":
            ret.append(c)
        elif c in ".:":
            ret.append("_")
        elif c == "/":
            ret.append("n")
        else:
            raise ValueError(f"invalid character in IP string: {c!r}")
    return "".join(ret)


class PaloAltoFirewallSession(FirewallSession[AddressGroupMetadata]):
    def consolidate_entries(
        self,
        entries: Dict[str, List[NetworkObjectEntry]],
    ) -> None:
        """
        Consolidates entries to make them more palatable for the firewall. Should not perform any
        external communication, neither with the CMDB nor with the firewall. Optional.

        On Palo Alto, merges the comments of addresses; otherwise, they are replaced there and back
        during every update.
        """

        addr_to_comments: DefaultDict[AnyIPNetwork, Set[str]] = defaultdict(set)

        for net_objects in entries.values():
            for net_object in net_objects:
                addr_to_comments[net_object.ip].add(net_object.comment)

        for net_objects in entries.values():
            for net_object in net_objects:
                net_object.comment = ", ".join(sorted(addr_to_comments[net_object.ip]))


    def obtain_firewall_metadata(
        self,
        address_versions: AbstractSet[int],
    ) -> Dict[str, AddressGroupMetadata]:
        firewall_config = self.config['firewall']

        try:
            allowed_names: List[str] = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            addr_groups_config = firewall_config['addr_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            name_format_ipv4: str = addr_groups_config['name_format_ipv4']
            name_format_ipv6: str = addr_groups_config['name_format_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.objects.{ex.args[0]}")

        addr_group_names_vers: List[Tuple[str, int]] = []
        if 4 in address_versions:
            addr_group_names_vers.extend((name_format_ipv4.format(n), 4) for n in allowed_names)
        if 6 in address_versions:
            addr_group_names_vers.extend((name_format_ipv6.format(n), 6) for n in allowed_names)

        ret: Dict[str, AddressGroupMetadata] = {}
        for addr_group_name, ip_ver in addr_group_names_vers:
            group_info = _obtain_group_definition(self.config, addr_group_name)
            if group_info is None:
                # address group does not (yet) exist
                # this might be intentional; Palo doesn't allow empty address groups
                ret[addr_group_name] = AddressGroupMetadata(
                    exists=False,
                    description="",
                    ip_ver=ip_ver,
                )
                continue

            # get description
            description = group_info.get('description', None)
            ret[addr_group_name] = AddressGroupMetadata(
                exists=True,
                description=description,
                ip_ver=ip_ver,
            )

        return ret


    def obtain_firewall_entries(self) -> Dict[str, List[NetworkObjectEntry]]:
        firewall_config: Dict[str, Any] = self.config['firewall']

        try:
            addr_groups_config: Dict[str, Any] = firewall_config['addr_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            allowed_names: List[str] = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            name_format_ipv4: str = addr_groups_config['name_format_ipv4']
            name_format_ipv6: str = addr_groups_config['name_format_ipv6']
            sentinel_ipv4: str = addr_groups_config['sentinel_ipv4']
            sentinel_ipv6: str = addr_groups_config['sentinel_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.objects.{ex.args[0]}")

        addr_group_names: List[Tuple[str, str]] = []
        addr_group_names.extend((n, name_format_ipv4.format(n)) for n in allowed_names)
        addr_group_names.extend((n, name_format_ipv6.format(n)) for n in allowed_names)

        # get all addresses
        name_to_addr = _obtain_name_to_addr(self.config)

        services_to_entries: Dict[str, List[NetworkObjectEntry]] = {}
        for service_name, addr_group_name in addr_group_names:
            try:
                service_entries = services_to_entries[service_name]
            except KeyError:
                service_entries = []
                services_to_entries[service_name] = service_entries

            service_entries.extend(_obtain_entries_for_group(
                self.config,
                addr_group_name,
                name_to_addr,
            ))

            # sentinel entries are a Palo implementation detail
            # do not leak them outside of the module
            sentinel_entries = {
                entry for entry in service_entries
                if entry.additional_info is not None
                and entry.additional_info["name"] in (sentinel_ipv4, sentinel_ipv6)
            }
            for sentinel_entry in sentinel_entries:
                service_entries.remove(sentinel_entry)

        return services_to_entries


    def implement_diff_on_firewall(
        self,
        diff: FirewallDiff,
        object_name: str,
        address_versions: AbstractSet[int],
    ) -> None:
        logger = loggage.get_logger(__name__)

        firewall_config: Dict[str, Any] = self.config['firewall']

        try:
            addr_groups_config: Dict[str, Any] = firewall_config['addr_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            addr_prefix_ipv4: str = addr_groups_config['addr_prefix_ipv4']
            addr_prefix_ipv6: str = addr_groups_config['addr_prefix_ipv6']
            sentinel_ipv4: str = addr_groups_config['sentinel_ipv4']
            sentinel_ipv6: str = addr_groups_config['sentinel_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.addr_groups.{ex.args[0]}")

        if object_name.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
            raise ValueError(
                f"refusing to modify object {object_name!r}; it is not in the list of allowed names"
            )

        # obtain the current state of affairs
        v4_group_name = addr_groups_config['name_format_ipv4'].format(object_name)
        v6_group_name = addr_groups_config['name_format_ipv6'].format(object_name)

        name_to_addr = _obtain_name_to_addr(self.config)
        v4_group_def = _obtain_group_definition(self.config, v4_group_name)
        v6_group_def = _obtain_group_definition(self.config, v6_group_name)

        v4_group_is_new = v4_group_def is None
        v6_group_is_new = v6_group_def is None

        dirty_status: Dict[int, bool] = {
            4: False,
            6: False,
        }

        if v4_group_is_new:
            v4_group_def = {
                "@name": v4_group_name,
                "static": {
                    "member": [sentinel_ipv4],
                },
            }

        else:
            assert v4_group_def is not None
            if sentinel_ipv4 not in v4_group_def["static"]["member"]:
                v4_group_def["static"]["member"].insert(0, sentinel_ipv4)
                dirty_status[4] = True

        if v6_group_is_new:
            v6_group_def = {
                "@name": v6_group_name,
                "static": {
                    "member": [sentinel_ipv6],
                },
            }
        else:
            assert v6_group_def is not None
            if sentinel_ipv6 not in v6_group_def["static"]["member"]:
                v6_group_def["static"]["member"].insert(0, sentinel_ipv6)
                dirty_status[6] = True

        try_remove_addrs: Set[str] = set()
        keep_addrs: Set[str] = set()

        for (op, old_entry, new_entry) in diff:
            not_none_entry = old_entry or new_entry
            if not_none_entry is None:
                continue

            if not_none_entry.ip.version not in address_versions:
                logger.debug(f"{not_none_entry}: skipping due to disabled IP version")
                continue

            if old_entry is not None and new_entry is not None \
                    and old_entry.ip.version != new_entry.ip.version:
                raise ValueError(
                    f"old_entry {old_entry!r} and new_entry {new_entry!r} differ in IP version!"
                )

            (this_group_name, this_group_def, this_addr_prefix) = {
                4: (v4_group_name, v4_group_def, addr_prefix_ipv4),
                6: (v6_group_name, v6_group_def, addr_prefix_ipv6),
            }[not_none_entry.ip.version]

            if op == "/":
                # directly update comment at address
                assert old_entry is not None
                assert old_entry.additional_info is not None
                assert new_entry is not None

                logger.debug(f'updating comment at {old_entry.ip_string} ({old_entry.additional_info["name"]!r})')

                addr_name = old_entry.additional_info["name"]
                addr_def = _obtain_addr_definition(self.config, addr_name)
                assert addr_def is not None

                logger.debug(f"defn: {json.dumps(addr_def)}")
                addr_def["description"] = new_entry.comment

                _firewall_request(
                    firewall_config,
                    LOCATION_TO_ADDRESS_ENDPOINT_PATH_FORMAT,
                    {"name": addr_name},
                    method="PUT",
                    json_body={"entry": addr_def},
                )

                keep_addrs.add(addr_name)

            if op == '-':
                # remove entry
                assert old_entry is not None
                assert old_entry.additional_info is not None

                logger.debug(f'removing {old_entry.ip_string} ({old_entry.additional_info["name"]!r}) from {this_group_name}')
                entry_name: str = old_entry.additional_info["name"]
                this_group_def["static"]["member"].remove(entry_name)

                # we might not need this address anymore
                try_remove_addrs.add(entry_name)

                dirty_status[old_entry.ip.version] = True

            if op == '+':
                assert new_entry is not None

                # add entry
                logger.debug(f'adding {new_entry.ip_string} to {this_group_name}')

                ip_name = this_addr_prefix + _sanitize_addr_name(new_entry.ip_string)
                if ip_name not in name_to_addr:
                    # this address does not exist yet; create it
                    addr_def = {
                        "entry": {
                            "@name": ip_name,
                            "ip-netmask": new_entry.ip_string,
                            "description": new_entry.comment,
                        },
                    }
                    _firewall_request(
                        firewall_config,
                        LOCATION_TO_ADDRESS_ENDPOINT_PATH_FORMAT,
                        {"name": ip_name},
                        method="POST",
                        json_body=addr_def,
                    )

                    # remember it in case it crops up later
                    name_to_addr[ip_name] = NetworkObjectEntry(
                        ip=ipaddress.ip_network(new_entry.ip_string),
                        comment=new_entry.comment,
                        additional_info={
                            "name": ip_name,
                        },
                    )

                # add it as a member
                this_group_def["static"]["member"].append(ip_name)

                # we are going to need it after all
                keep_addrs.add(ip_name)

                dirty_status[new_entry.ip.version] = True

        # create or update the groups
        groups = (
            (4, v4_group_is_new, v4_group_name, v4_group_def),
            (6, v6_group_is_new, v6_group_name, v6_group_def),
        )
        for (ip_ver, is_new, name, definition) in groups:
            method: Optional[str] = None
            body: Optional[Dict[str, Any]] = {'entry': definition}

            if is_new:
                if definition["static"]["member"]:
                    # group does not exist, has entries => create
                    logger.debug(f"creating IPv{ip_ver} group ({name!r})")
                    method = "POST"
                else:
                    # group does not exist, empty => ignore
                    logger.debug(f"IPv{ip_ver} group ({name!r}) is new and empty; ignoring")
            elif dirty_status[ip_ver]:
                if definition["static"]["member"]:
                    # group exists, has entries => replace
                    logger.debug(f"updating IPv{ip_ver} group ({name!r})")
                    method = "PUT"
                else:
                    # group exists, empty => delete
                    logger.debug(f"IPv{ip_ver} group ({name!r}) exists and is empty; deleting")
                    method = "DELETE"
                    body = None

            if method is not None:
                add_params: Dict[str, Any] = {}
                if body is not None:
                    add_params['json_body'] = body

                _firewall_request(
                    firewall_config,
                    LOCATION_TO_ADDRESS_GROUP_ENDPOINT_PATH_FORMAT,
                    {'name': name},
                    method=method,
                    **add_params
                )

        if not any(dirty_status.values()):
            # if nothing changed, no need to cleanup, commit or push
            return

        # remove old addresses
        try_remove_addrs.difference_update(keep_addrs)
        for addr_to_remove in try_remove_addrs:
            logger.debug(f"deleting removed address {addr_to_remove!r}")
            code, j = _firewall_request(
                firewall_config,
                LOCATION_TO_ADDRESS_ENDPOINT_PATH_FORMAT,
                {'name': addr_to_remove},
                method="DELETE",
                expected_codes={200, 400},
            )
            if code == 400:
                assert j is not None
                if j['code'] == OBJECT_STILL_REFERENCED_CODE:
                    logger.debug("address not deleted; it is still being referenced")
                else:
                    raise ValueError(f"failed to delete removed address {addr_to_remove!r}: {j!r}")


    def construct_full_firewall_lists(
        self,
        services_lists: Mapping[str, List[NetworkObjectEntry]],
        objects_metadata: Mapping[str, AddressGroupMetadata],
        address_versions: AbstractSet[int],
    ) -> Mapping[str, Mapping[str, Any]]:
        logger = loggage.get_logger(__name__)

        addr_groups_config = self.config['firewall']['addr_groups']

        try:
            addr_prefix_ipv4: str = addr_groups_config['addr_prefix_ipv4']
            addr_prefix_ipv6: str = addr_groups_config['addr_prefix_ipv6']
            sentinel_ipv4: str = addr_groups_config['sentinel_ipv4']
            sentinel_ipv6: str = addr_groups_config['sentinel_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.addr_groups.{ex.args[0]}")

        names_to_final_groups: Dict[str, Any] = {}
        names_to_addresses: Dict[str, Any] = {}

        # prepare lists
        for name, metadata in objects_metadata.items():
            sentinel_addr: str = {
                4: sentinel_ipv4,
                6: sentinel_ipv6,
            }[metadata.ip_ver]

            names_to_final_groups[name] = {
                "@name": name,
                "static": {
                    "member": [sentinel_addr],
                },
            }

        for service, entries in services_lists.items():
            if service.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
                raise ValueError(
                    f"refusing to modify network object {service!r}; it is not in the list of allowed"
                    " names"
                )

            for entry in sorted(entries, key=lambda e: e.comparison_key):
                if entry.ip.version not in address_versions:
                    logger.debug(f"{entry}: skipping due to disabled IP version")
                    continue

                name_format = addr_groups_config[f'name_format_ipv{entry.ip.version}']
                name = name_format.format(service)

                this_addr_prefix = {
                    4: addr_prefix_ipv4,
                    6: addr_prefix_ipv6,
                }[entry.ip.version]
                ip_name = this_addr_prefix + _sanitize_addr_name(entry.ip_string)

                names_to_final_groups[name]['static']['member'].append(ip_name)

                names_to_addresses[ip_name] = {
                    "@name": ip_name,
                    "ip-netmask": entry.ip_string,
                    "description": entry.comment,
                }

        return {
            "addresses": names_to_addresses,
            "address_groups": names_to_final_groups,
        }


    @property
    def can_replace_lists(self) -> bool:
        return False


    def replace_lists_on_firewall(
        self,
        names_to_objects: Mapping[str, Mapping[str, Any]],
    ) -> None:
        raise NotImplementedError(
            "the Palo Alto API is not conducive to full-list replacement; please use the standard"
            " operating mode"
        )


    def commit_changes(self) -> None:
        """
        Commits all pending changes, activating them on the firewall.
        """
        firewall_config: Dict[str, Any] = self.config['firewall']

        try:
            username: str = firewall_config['username']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        push_device_group: Optional[str] = firewall_config.get('push_device_group', None)

        commit_xml_text = COMMIT_XML_FORMAT.format(
            username=_escape_xml(username),
        )
        commit_path = COMMIT_PATH_FORMAT.format(
            xml=urllib.parse.quote_plus(commit_xml_text),
        )
        _status, commit_result = _firewall_xml_request(self.config, commit_path)

        logger = loggage.get_logger(__name__)

        logger.debug(f"commit response: {defused_to_string(commit_result)}")

        if (
            commit_result.attrib.get("status", None) == "success"
            and commit_result.attrib.get("code", None) == "13"
        ):
            logger.debug(f"commit operation with no changes: {commit_result.find('./msg').text}")
            return

        if (
            commit_result.attrib.get("status", None) == "success"
            and commit_result.attrib.get("code", None) == "19"
        ):
            # job enqueued
            job_elem = commit_result.find("./result/job")
            job_no = job_elem.text

            logger.debug(f"commit enqueued as job {job_no}")

            # wait until commit completes
            _wait_for_job_completion(self.config, job_no)

        else:
            raise ValueError(f"commit failed: {defused_to_string(commit_result)}")


        if push_device_group is not None:
            push_xml_text = PUSH_XML_FORMAT.format(
                device_group=_escape_xml(push_device_group),
            )
            push_path = PUSH_PATH_FORMAT.format(
                xml=urllib.parse.quote_plus(push_xml_text),
            )
            _status, push_result = _firewall_xml_request(self.config, push_path)

            logger.debug(f"push response: {defused_to_string(push_result)}")

            if (
                push_result.attrib.get("status", None) == "success"
                and push_result.attrib.get("code", None) == "13"
            ):
                logger.debug(f"push operation with no changes: {push_result.find('./msg').text}")
                return

            if (
                push_result.attrib.get("status", None) == "success"
                and push_result.attrib.get("code", None) == "19"
            ):
                job_elem = push_result.find("./result/job")
                job_no = job_elem.text

                logger.debug(f"push enqueued as job {job_no}")

                _wait_for_job_completion(self.config, job_no)


def make_api_session(config: Dict[str, Any]) -> PaloAltoFirewallSession:
    return PaloAltoFirewallSession(config)
