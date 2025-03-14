"""
# tuitfw.cmdb.aixboms

Enables obtaining firewall rules from the AixBOMS configuration management database, from the
firewall configuration blocks stored in the firewall field of object Post-Its.

## Configuration

The following configuration stanzas are recognized in the `cmdb` section if `type` is set to
`aixboms`:

* `server` is the name of the database to which to connect. It is recommended to use an Oracle
  EasyConnect descriptor (`hostname[:port]/service`).
* `username` is the username with which to connect to the database.
* `password` is the password with which to authenticate when connecting to the database.
* `scope` is the scope for which to process rules. By requiring a `scope` attribute on each entry in
  the firewall field of an object Post-It, multiple firewalls can be configured from the same data
  source. Entries whose scope is not the one set in the configuration file are not processed.
"""

import io
import ipaddress
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple
import yaml
from .. import loggage
from ..common import NetworkObjectEntry
from ..db import oracle


LEADING_ZERO_RE = re.compile('\\b0+([1-9])')


def connect_to_database_from_config(config: Dict[str, Any]):
    return oracle.connect_to_database_from_config(config['cmdb'])


def obtain_database_entries(db_conn: Any, config: Mapping[str, Any]) \
        -> Dict[str, List[NetworkObjectEntry]]:
    """
    Obtains the allow-list entries from the AixBOMS database and returns them as a dictionary
    mapping sanitized service names (uppercase with stripped leading and trailing spaces) to lists
    of NetworkObjectEntry instances.
    """
    our_scope = config['cmdb']['scope']

    allowed_object_names = config.get('common', {}).get('allowed_object_names', None)
    allowed_object_upper_to_regular = {on.upper(): on for on in allowed_object_names} \
        if allowed_object_names is not None else None

    cur = db_conn.cursor()

    object_types = {
        'C': 'component',
        'R': 'connector',
        'v': 'IPv4 address', # *v*ier
        'V': 'IPv4 network',
        's': 'IPv6 address', # *s*echs
        'S': 'IPv6 network',
    }
    cur.execute("""
        SELECT
            'C' obj_type,
            COALESCE(pitcomp.bezeichnung, pitcomp.id) name,
            pitcomp.ipv4_adresse ipv4_address,
            pitcomp.ipv6_adresse ipv6_address,
            pitcomp.firewallinfo firewall_info,
            'comp_' || pitcomp.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_component_v pitcomp
        WHERE
            pitcomp.firewallinfo IS NOT NULL

        UNION ALL

        SELECT
            'R' obj_type,
            pitcn.komponenten_id || ' ' || COALESCE(pitcn.bezeichnung, pitcn.id) name,
            pitcn.komponenten_ipv4_adresse ipv4_address,
            pitcn.komponenten_ipv6_adresse ipv6_address,
            pitcn.firewallinfo firewall_info,
            'cn_' || pitcn.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_connector_v pitcn
        WHERE
            pitcn.firewallinfo IS NOT NULL

        UNION ALL

        SELECT
            'v' obj_type,
            case
                when ip4hn.hostname is null then COALESCE(pit4a.bezeichnung, pit4a.id)
                else ip4hn.hostname || ' ' || COALESCE(pit4a.bezeichnung, pit4a.id)
            end name,
            pit4a.ip_adresse ipv4_address,
            null ipv6_address,
            pit4a.firewallinfo firewall_info,
            'ipv4addr_' || pit4a.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_ipv4_address_v pit4a
            LEFT OUTER JOIN aixboms_admin.coco_netaddress_v ip4a
                ON ip4a.ip_string = pit4a.ip_adresse
                AND ip4a.list_enabled = 1
            LEFT OUTER JOIN aixboms_admin.coco_netadr_2_hostname_v ip4hn
                ON ip4hn.netaddress_obj_no = ip4a.netaddress_obj_no
                AND ip4hn.position = 0
                AND ip4hn.list_enabled = 1
        WHERE
            pit4a.firewallinfo IS NOT NULL

        UNION ALL

        SELECT
            's' obj_type,
            case
                when ip6a.hostname is null then COALESCE(pit6a.bezeichnung, pit6a.id)
                else ip6a.hostname || ' ' || COALESCE(pit6a.bezeichnung, pit6a.id)
            end name,
            null ipv4_address,
            pit6a.ip_adresse ipv6_address,
            pit6a.firewallinfo firewall_info,
            'ipv6addr_' || pit6a.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_ipv6_address_v pit6a
            LEFT OUTER JOIN aixboms_admin.coco_netaddress_v ip6a
                ON ip6a.ipv6_string = pit6a.ip_adresse
            LEFT OUTER JOIN aixboms_admin.coco_netadr_2_hostname_v ip6hn
                ON ip6hn.netaddress_obj_no = ip6a.netaddress_obj_no
                AND ip6hn.position = 0
                AND ip6hn.list_enabled = 1
        WHERE
            pit6a.firewallinfo IS NOT NULL

        UNION ALL

        SELECT
            'V' obj_type,
            pit4n.id name,
            net4.netaddress_string || '/' || net4.netmask_string ipv4_address,
            null ipv6_address,
            pit4n.firewallinfo firewall_info,
            'ipv4net_' || pit4n.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_ipv4_network_v pit4n
            INNER JOIN aixboms_admin.coco_network_v net4
                ON net4.network_obj_no = pit4n.obj_nr
                AND net4.list_enabled = 1
        WHERE
            pit4n.firewallinfo IS NOT NULL

        UNION ALL

        SELECT
            'S' obj_type,
            pit6n.id name,
            null ipv4_address,
            net6.netaddress_string || '/' || net6.netmask_string ipv6_address,
            pit6n.firewallinfo firewall_info,
            'ipv6net_' || pit6n.id obj_identifier
        FROM
            aixboms_admin.tuw_if_postit_ipv6_network_v pit6n
            INNER JOIN aixboms_admin.coco_network_v net6
                ON net6.network_obj_no = pit6n.obj_nr
                AND net6.list_enabled = 1
        WHERE
            pit6n.firewallinfo IS NOT NULL
    """)
    services_to_entries: Dict[str, List[NetworkObjectEntry]] = {}
    for postit_tuple in cur:
        process_database_entry(
            object_types, services_to_entries, postit_tuple, our_scope,
            allowed_object_upper_to_regular
        )

    return services_to_entries


def _ipv6_net_with_mask_to_cidr(ipv6_net_with_mask: str) -> str:
    """
    Converts an IPv6-with-subnet-mask network definition (e.g. "2001:db8::/ffff:ffff::") to its
    CIDR representation ("2001:db8::/32", respectively), since the ipaddress.IPv6Network constructor
    does not like the mask syntax.
    """
    pieces = ipv6_net_with_mask.split("/", 1)
    if len(pieces) == 1:
        # probably no netmask at all
        return ipv6_net_with_mask
    if ":" not in pieces[1]:
        # probably not an IPv6 netmask
        return ipv6_net_with_mask

    prefix_bits = 0
    zero_bit_encountered = False
    mask = ipaddress.IPv6Address(pieces[1])
    for b in mask.packed:
        if b == 0xFF:
            if zero_bit_encountered:
                raise ValueError(f"non-prefix subnet mask {mask} is not supported")
            prefix_bits += 8
        elif b == 0x00:
            zero_bit_encountered = True
        else:
            # mixed byte
            for i in reversed(range(8)):
                if b & (1 << i) == 0:
                    zero_bit_encountered = True
                else:
                    # one-bit
                    if zero_bit_encountered:
                        # ... following zero-bit
                        raise ValueError(f"non-prefix subnet mask {mask} is not supported")
                    prefix_bits += 1

    return f"{pieces[0]}/{prefix_bits}"


def process_database_entry(object_types: Dict[str, str],
                           services_to_entries: Dict[str, List[NetworkObjectEntry]],
                           postit_tuple: Tuple, our_scope: str,
                           allowed_service_group_upper_to_regular: Optional[Dict[str, str]]) -> None:
    logger = loggage.get_logger(__name__)

    # unpack
    (
        obj_type, obj_id, ipv4_addr, ipv6_addr, firewall_info_str, obj_ident
    ) = postit_tuple

    if obj_type == 'v':
        # IPv4 address
        obj_key = ipv4_addr
    elif obj_type == 's':
        # IPv6 address
        obj_key = ipv6_addr
    else:
        obj_key = None

    if obj_key is not None:
        obj_descriptor = f"{object_types[obj_type]} {obj_key} ({obj_id!r})"
    else:
        obj_descriptor = f"{object_types[obj_type]} {obj_id!r}"

    # parse YAML
    with io.StringIO(firewall_info_str) as firewall_info_io:
        try:
            firewall_info = yaml.safe_load(firewall_info_io)
        except yaml.error.YAMLError:
            logger.error(
                f"{obj_descriptor}: failed to parse firewall info as YAML; skipping whole Post-It"
            )
            return

    if firewall_info is None:
        # yaml.safe_load returns None if the YAML document is just a sequence of comments
        # consider it equivalent to an empty list
        firewall_info = []

    if not hasattr(firewall_info, 'append'):
        logger.error(
            f"{obj_descriptor}: firewall info is not a list; skipping whole Post-It"
        )
        return

    for entry_index, entry in enumerate(firewall_info):
        # obtain scope
        try:
            entry_scope = entry['scope']

        except TypeError:
            logger.error(
                f"{obj_descriptor}: firewall info is not a list of mappings; skipping whole Post-It"
            )
            return

        except KeyError:
            logger.warning(
                f"{obj_descriptor}: entry at index {entry_index}: missing scope; skipping entry"
            )
            continue

        # check scope
        if entry_scope != our_scope:
            continue

        # is the rule disabled?
        if not entry.get('enabled', True):
            continue

        # is an IP address set?
        addr_string = entry.get('address', None)
        if addr_string is None:
            # no; take it from the object
            ip_version = entry.get('ip_version', 4)
            if ip_version not in (4, 6):
                logger.error(
                    f"{obj_descriptor}: entry at index {entry_index}: "
                    f"invalid value for ip_version, should be the number 4 or the number 6; "
                    f"skipping entry"
                )
                continue

            obj_ip_addr = ipv4_addr if ip_version == 4 else ipv6_addr
            if obj_ip_addr is None:
                logger.error(
                    f"{obj_descriptor}: entry at index {entry_index}: "
                    f"IPv{ip_version} address neither explicitly specified in entry nor set on "
                    f"object; skipping entry"
                )
                continue

            addr_string = obj_ip_addr

        else:
            # yes, we have an explicitly set IP address
            if 'ip_version' in entry:
                logger.warning(
                    f"{obj_descriptor}: entry at index {entry_index}: "
                    f"both ip_version and address attributes specified; ignoring ip_version "
                    f"attribute"
                )
                # keep processing

        # parse address
        try:
            ip = ipaddress.ip_network(_ipv6_net_with_mask_to_cidr(addr_string))
        except ValueError:
            logger.error(
                f"{obj_descriptor}: entry at index {entry_index}: "
                f"failed to parse {addr_string!r} as an IP address; skipping entry"
            )
            continue

        # obtain service groups
        try:
            service_groups = entry['service_groups']
        except KeyError:
            logger.error(
                f"{obj_descriptor}: entry at index {entry_index}: "
                f"missing service_groups attribute; skipping entry"
            )
            continue

        # store per service group
        for service_group_index, service_group_db in enumerate(service_groups):
            service_group_db_upper = service_group_db.upper()
            if allowed_service_group_upper_to_regular is not None:
                try:
                    service_group = allowed_service_group_upper_to_regular[service_group_db_upper]
                except KeyError:
                    logger.error(
                        f"{obj_descriptor}: entry at index {entry_index}: "
                        f"service group name at index {service_group_index}: invalid service group "
                        f"{service_group_db!r}; not adding this entry to this service group"
                    )
                    continue

            try:
                entries = services_to_entries[service_group]
            except KeyError:
                entries = []
                services_to_entries[service_group] = entries

            preexisting = [
                noe
                for noe
                in entries
                if (noe.ip.network_address, noe.ip.prefixlen) == (ip.network_address, ip.prefixlen)
            ]
            if len(preexisting) > 0:
                # okay, we have already handled this address
                # did it come from a different object?
                is_different_object = any(
                    p.identifier != obj_ident
                    for p in preexisting
                )
                if is_different_object:
                    # yes; warn
                    logger.warning(
                        f"{obj_descriptor}: entry at index {entry_index}: "
                        f"service group at index {service_group_index}: duplicate entry: "
                        f"{ip.network_address!r}/{ip.prefixlen!r} in service group "
                        f"{service_group} is already known from {preexisting[0].comment}"
                    )

                # (otherwise, accept it as an annoying quirk of the database query)

                # let the firewall module decide how to handle such duplicates

            entries.append(NetworkObjectEntry(ip, f"{obj_type} {obj_id} {entry_index}", identifier=obj_ident))
