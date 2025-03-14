"""
# tuitfw.fw.barracuda

Communicates with a Barracuda CloudGen Firewall via the REST API to obtain and/or modify rules.

## Configuration

The following configuration stanzas are recognized in the `firewall` section if `type` is set to
`barracuda`:

* `base_uri` is the base URI of the Barracuda CloudGen Firewall REST API endpoint to contact. The
  paths to the respective endpoints are constructed relative to this base URI.
* `username` is the username with which to connect to the REST API endpoint.
* `password` is the password with which to authenticate when connecting to the REST API endpoint.
* `objects` defines which network objects are modified and how. It is documented later in this
  section.

#### objects subsection

The `objects` subsection defines which network objects are modified and how.

* `type` is the type of network object to modify. It is one of the following:
  * `cc-global`
  * `cc-range`
  * `cc-cluster`
  * `cc-cluster-box`
  * `cc-cluster-server-service`
  * `cc-cluster-server-service-shared`
  * `cc-cluster-shared-service`
  * `fw`
  * `fw-server-service`
* type-specific options:
  * `range`, the name of the range.
  * `cluster`, the name of the cluster.
  * `server`, the name of the virtual server.
  * `box`, the name of the box.
  * `service`, the name of the service.
  * `ruleset`, the type of ruleset to access. Can be one of `global`, `local`, or `special`.
* `name_format_ipv4` is a Python format string (`str.format`) to transform a database network
  object name (as listed in `common.allowed_object_names`) to the name of the firewall network
  object to be populated with IPv4 addresses. The database network object name is passed as
  positional argument 0. For example, `"NETDBV4-{0}"` transforms `ALL` into `NETDBV4-ALL`.
* `name_format_ipv6` is the IPv6 counterpart to `name_format_ipv4`.

The following table illustrates which type-specific options are required with which types:

| `type`                             | `range`  | `cluster` | `server` | `box`    | `service` | `ruleset` |
| ---------------------------------- | -------- | --------- | -------- | -------- | --------- | --------- |
| `cc-global`                        |          |           |          |          |           |           |
| `cc-range`                         | required |           |          |          |           |           |
| `cc-cluster`                       | required | required  |          |          |           |           |
| `cc-cluster-box`                   | required | required  |          | required |           |           |
| `cc-cluster-server-service`        | required | required  | required |          | required  |           |
| `cc-cluster-server-service-shared` | required | required  | required |          | required  | required  |
| `cc-cluster-shared-service`        | required | required  |          |          | required  | required  |
| `fw`                               |          |           |          |          |           |           |
| `fw-server-service`                |          |           | required |          | required  |           |
"""

import ipaddress
import json
from typing import AbstractSet, Any, Dict, List, Mapping, Optional, Tuple
import urllib.parse
import requests
from . import FirewallSession
from .. import loggage
from ..common import AnyIPNetwork, FirewallDiff, NetworkObjectEntry, raise_config_missing_key


TYPES_TO_ENDPOINT_PATH_FORMATS = {
    'cc-global': '/rest/firewall/v1/cc/global/objects/networks',
    'cc-range': '/rest/firewall/v1/cc/ranges/{range}/objects/networks',
    'cc-cluster': '/rest/firewall/v1/cc/ranges/{range}/clusters/{cluster}/objects/networks',
    'cc-cluster-box': '/rest/firewall/v1/cc/ranges/{range}/clusters/{cluster}/boxes/{box}/objects/networks',
    'cc-cluster-server-service': '/rest/firewall/v1/cc/ranges/{range}/clusters/{cluster}/servers/{server}/services/{service}/objects/networks',
    'cc-cluster-server-service-shared': '/rest/firewall/v1/cc/ranges/{range}/clusters/{cluster}/servers/{server}/services/{service}/{ruleset}/objects/networks',
    'cc-cluster-shared-service': '/rest/firewall/v1/cc/ranges/{range}/clusters/{cluster}/services/{service}/{ruleset}/objects/networks',
    'fw': '/rest/firewall/v1/objects/networks',
    'fw-server-service': '/rest/firewall/v1/servers/{server}/services/{service}/objects/networks'
}


class FirewallListMetadata:
    """Metadata of a firewall object list."""

    def __init__(self, list_type: str, comment: str):
        self.list_type = list_type
        self.comment = comment

    def __repr__(self) -> str:
        return f"FirewallListMetadata(list_type={self.list_type!r}, comment={self.comment!r})"


def join_barracuda_uri(base_uri: str, firewall_objects_config: Mapping[str, Any]) -> str:
    """
    Joins a Barracuda REST base URI with the necessary path components as specified in the given
    firewall object configuration dictionary and returns the full URI.
    """
    if 'type' not in firewall_objects_config:
        raise_config_missing_key("firewall.objects.type")

    t = firewall_objects_config['type']
    try:
        path_format = TYPES_TO_ENDPOINT_PATH_FORMATS[t]
    except KeyError:
        # pylint: disable=raise-missing-from
        raise KeyError(f"unknown firewall object type {t!r}")

    try:
        path = path_format.format(**firewall_objects_config)
    except KeyError as ex:
        raise_config_missing_key(f"firewall.objects.{ex.args[0]}", f"for type {t!r}")

    return urllib.parse.urljoin(base_uri, path)



def firewall_request(firewall_config: Mapping[str, Any], uri_tail: str, method: str = "GET",
                     json_body: Optional[Any] = None,
                     add_headers: Optional[Mapping[str, str]] = None) -> Optional[Dict[str, Any]]:
    try:
        (top_base_uri, username, password, ca_cert_location, objects_config) = (
            firewall_config['base_uri'],
            firewall_config['username'],
            firewall_config['password'],
            firewall_config.get('ca_cert_location', False),
            firewall_config['objects']
        )
    except KeyError as ex:
        raise_config_missing_key(f"firewall.{ex.args[0]}")

    base_uri = join_barracuda_uri(top_base_uri, objects_config)
    uri = base_uri + uri_tail

    headers = dict(add_headers) if add_headers is not None else {}
    headers['Accept'] = 'application/json'

    addenda = {}
    if json_body is not None:
        addenda['json'] = json_body

    logger = loggage.get_logger(__name__)
    logger.debug(f"firewall request: {method} {uri}")
    response = requests.request(method, uri, auth=(username, password), headers=headers,
                                verify=ca_cert_location, **addenda)
    if response.status_code != 200:
        # bad
        logger.critical(
            f"failed to obtain server data (HTTP {response.status_code}): {response.text}"
        )
    return response.json() if len(response.content) > 0 else None


def correct_barracuda_ipv6_netmask(ipv6_net_string: str) -> str:
    # IPv6 netmasks used to be calculated incorrectly by the Barracuda REST responder
    # this is no longer the case after upgrading from 7.1.1 to 7.2.3
    #if '/' in ipv6_net_string:
    #    (ipv6_addr, wrong_ipv6_prefix) = ipv6_net_string.split('/', 1)
    #    correct_ipv6_prefix = 32 - int(wrong_ipv6_prefix)
    #    ipv6_net_string = f"{ipv6_addr}/{correct_ipv6_prefix}"
    return ipv6_net_string


def address_with_barracuda_ipv6_netmask(entry: NetworkObjectEntry) -> str:
    if not entry.is_subnet:
        # IPv4 or IPv6 host
        return str(entry.ip.network_address)

    elif entry.ip.version == 6:
        # IPv6 subnet
        # recalculation is still necessary here despite upgrading from 7.1.1 to 7.2.3
        wrong_ipv6_prefix = 32 - entry.ip.prefixlen
        return f"{entry.ip.network_address.compressed}/{wrong_ipv6_prefix}"

    else:
        # IPv4 subnet
        return str(entry.ip)


def network_object_to_barracuda_json_ready(net_obj: NetworkObjectEntry) -> Any:
    if net_obj.ip.version == 4:
        if net_obj.is_subnet:
            # adding ipV4 entries requires the prefix's complement
            # 2019-03-05: this is no longer the case with 7.2.3, as we learned the hard way
            return {
                #'type': 'networkV4',
                'type': 'ipV4',
                #'ipV4': f"{net_obj.ip.network_address.compressed}/{32 - net_obj.ip.prefixlen}",
                'ipV4': f"{net_obj.ip.network_address.compressed}/{net_obj.ip.prefixlen}",
                'comment': net_obj.comment,
            }
        else:
            return {
                'type': 'ipV4',
                'ipV4': net_obj.ip.network_address.compressed,
                'comment': net_obj.comment,
            }
    elif net_obj.ip.version == 6:
        return {
            'type': 'ipV6',
            'ipV6': f"{net_obj.ip_string}",
            'comment': net_obj.comment,
        }
    else:
        raise ValueError(f"unsupported IP version {net_obj.ip.version}")


class BarracudaFirewallSession(FirewallSession[FirewallListMetadata]):
    def obtain_firewall_metadata(self, address_versions: AbstractSet[int]) -> Dict[str, FirewallListMetadata]:
        firewall_config = self.config['firewall']

        try:
            allowed_names = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            objects_config = firewall_config['objects']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            name_format_ipv4 = objects_config['name_format_ipv4']
            name_format_ipv6 = objects_config['name_format_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.objects.{ex.args[0]}")

        object_names = []
        if 4 in address_versions:
            object_names += [name_format_ipv4.format(n) for n in allowed_names]
        if 6 in address_versions:
            object_names += [name_format_ipv6.format(n) for n in allowed_names]

        ret = {}
        for object_name in object_names:
            object_name_enc = urllib.parse.quote(object_name, safe='')
            j = firewall_request(firewall_config, f"/{object_name_enc}")
            assert j is not None

            # get type and comment
            try:
                list_type, comment = j['type'], j['comment']
            except KeyError as ex:
                raise KeyError(f"missing value {ex.args[0]!r} in response") from ex

            ret[object_name] = FirewallListMetadata(list_type, comment)

        return ret


    def obtain_firewall_entries(self) -> Dict[str, List[NetworkObjectEntry]]:
        logger = loggage.get_logger(__name__)

        firewall_config = self.config['firewall']

        try:
            allowed_names = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            objects_config = firewall_config['objects']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            name_format_ipv4 = objects_config['name_format_ipv4']
            name_format_ipv6 = objects_config['name_format_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.objects.{ex.args[0]}")

        object_names: List[Tuple[str, str]] = []
        object_names.extend((n, name_format_ipv4.format(n)) for n in allowed_names)
        object_names.extend((n, name_format_ipv6.format(n)) for n in allowed_names)

        services_to_entries: Dict[str, List[NetworkObjectEntry]] = {}
        for service_name, object_name in object_names:
            object_name_enc = urllib.parse.quote(object_name, safe='')
            j = firewall_request(firewall_config, f"/{object_name_enc}")
            assert j is not None

            if len(j['excluded']):
                # this should ideally never happen (i.e. only if an NGAdmin user is too creative for
                # their own good), but we should output a warning anyway
                logger.warning(
                    f"firewall object {object_name!r} contains addresses in the 'excluded' section; "
                    f"this makes a lot of people very angry and is widely regarded as a bad move"
                )

            try:
                this_service_entries = services_to_entries[service_name]
            except KeyError:
                this_service_entries = []
                services_to_entries[service_name] = this_service_entries

            for inc in j['included']:
                if inc['type'] in ('ipV4', 'networkV4'):
                    ip: AnyIPNetwork = ipaddress.IPv4Network(inc['ipV4'])
                elif inc['type'] == 'ipV6':
                    ipv6_net_string = inc['ipV6']

                    # HACK: IPv6 netmasks are calculated incorrectly by older versions
                    # of the Barracuda REST responder
                    ipv6_net_string = correct_barracuda_ipv6_netmask(ipv6_net_string)

                    ip = ipaddress.IPv6Network(ipv6_net_string)
                else:
                    # skip
                    continue
                comment = inc['comment']

                preexisting = [
                    noe
                    for noe
                    in this_service_entries
                    if (noe.ip.network_address, noe.ip.prefixlen) == (ip.network_address, ip.prefixlen)
                ]
                if len(preexisting) > 0:
                    logger.warning(
                        f"duplicate entry: {ip.network_address}/{ip.prefixlen} appears multiple times "
                        f"in the firewall object {object_name!r}"
                    )

                this_service_entries.append(NetworkObjectEntry(ip, comment))

        return services_to_entries


    def implement_diff_on_firewall(
        self,
        diff: FirewallDiff,
        object_name: str,
        address_versions: AbstractSet[int],
    ) -> None:
        logger = loggage.get_logger(__name__)

        firewall_config = self.config['firewall']

        objects_config = firewall_config['objects']

        if object_name.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
            raise ValueError(
                f"refusing to modify network object {object_name!r}; it is not in the list of allowed "
                f"names"
            )

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

            name_format = objects_config[f'name_format_ipv{not_none_entry.ip.version}']
            name = name_format.format(object_name)
            escaped_name = urllib.parse.quote(name, safe='')

            if op in ('-', '/'):
                assert old_entry is not None

                # remove (or replace = remove-then-add)
                logger.debug(f'removing {old_entry.ip_string} from {object_name}')

                # HACK: IPv6 netmasks are calculated incorrectly by the Barracuda REST responder
                barracuda_ip_string = address_with_barracuda_ipv6_netmask(old_entry)

                escaped_ip_string = urllib.parse.quote(barracuda_ip_string, safe=':')
                firewall_request(firewall_config, f"/{escaped_name}/included/{escaped_ip_string}",
                                 "DELETE")

            if op in ('+', '/'):
                assert new_entry is not None

                # add (or replace = remove-then-add)
                logger.debug(f'adding {new_entry.ip_string} to {object_name}')
                new_entry_json_ready = network_object_to_barracuda_json_ready(new_entry)
                logger.debug(f'  JSON: {json.dumps(new_entry_json_ready)}')
                firewall_request(firewall_config, f"/{escaped_name}/included", "POST",
                                 json_body=new_entry_json_ready)


    @property
    def can_replace_lists(self) -> bool:
        return True


    def construct_full_firewall_lists(
        self,
        services_lists: Mapping[str, List[NetworkObjectEntry]],
        objects_metadata: Mapping[str, FirewallListMetadata],
        address_versions: AbstractSet[int],
    ) -> Mapping[str, Mapping[str, Any]]:
        logger = loggage.get_logger(__name__)

        objects_config = self.config['firewall']['objects']

        names_to_final_objects: Dict[str, Dict[str, Any]] = {}

        # prepare lists
        for name, metadata in objects_metadata.items():
            names_to_final_objects[name] = {
                'name': name,
                'type': metadata.list_type,
                'comment': metadata.comment,
                'excluded': [],
                'included': [],
            }

        for service, entries in services_lists.items():
            if service.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
                raise ValueError(
                    f"refusing to modify network object {service!r}; it is not in the list of allowed "
                    f"names"
                )

            for entry in sorted(entries, key=lambda e: e.comparison_key):
                if entry.ip.version not in address_versions:
                    logger.debug(f"{entry}: skipping due to disabled IP version")
                    continue

                name_format = objects_config[f'name_format_ipv{entry.ip.version}']
                name = name_format.format(service)

                entry_json_ready = network_object_to_barracuda_json_ready(entry)
                names_to_final_objects[name]['included'].append(entry_json_ready)

        return names_to_final_objects


    def replace_lists_on_firewall(
        self,
        names_to_objects: Mapping[str, Mapping[str, Any]],
    ) -> None:
        firewall_config = self.config['firewall']
        for name, firewall_object in names_to_objects.items():
            escaped_name = urllib.parse.quote(name, safe='')
            firewall_request(firewall_config, f'/{escaped_name}', 'PUT', firewall_object)


    # Barracuda commits immediately

    # static token, so no login/logout


def make_api_session(config: Dict[str, Any]) -> BarracudaFirewallSession:
    return BarracudaFirewallSession(config)
