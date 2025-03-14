"""
# tuitfw.cmdb.tunetdb

Enables obtaining firewall rules from the TUNETDB configuration management database, from the values
stored in `ALIST/TUFW` and `ALIST/TUFW6` attributes.

## Configuration

The following configuration stanzas are recognized in the `cmdb` section if `type` is set to
`tunetdb`:

* `server` is the name of the database to which to connect. It is recommended to use an Oracle
  EasyConnect descriptor (`hostname[:port]/service`).
* `username` is the username with which to connect to the database.
* `password` is the password with which to authenticate when connecting to the database.
"""

import ipaddress
import re
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Mapping, Optional
from .. import loggage
from ..common import AnyIPNetwork, NetworkObjectEntry
from ..db import oracle


LEADING_ZERO_RE = re.compile('\\b0+([1-9])')


class TunetDbState(IntEnum):
    ACTIVE = 0
    TEMPLATE = 1
    VIRTUAL = 2
    REQUEST = 3 # Antrag
    DELETED = 4


def connect_to_database_from_config(config: Dict[str, Any]):
    return oracle.connect_to_database_from_config(config['cmdb'])


def obtain_object_id_to_full_name(db_cursor: Any, states: Optional[Iterable[TunetDbState]] = None) \
        -> Dict[int, str]:
    """
    Obtains the mapping of object IDs to their full names.
    """
    state_set = frozenset(states) if states is not None else frozenset()

    if not state_set:
        # any state
        states_criterion = None
    elif len(state_set) == 1:
        states_criterion = f"= {next(iter(state_set)).value}"
    else:
        states_string = ", ".join(str(state.value) for state in sorted(state_set))
        states_criterion = f"IN ({states_string})"

    if states_criterion is None:
        states_criterion_tail_t = ""
        states_criterion_tail_c = ""
    else:
        states_criterion_tail_t = f" AND t.state {states_criterion}"
        states_criterion_tail_c = f" AND c.state {states_criterion}"

    db_cursor.execute(f"""
        WITH object_full_names(id, full_name) AS (
            SELECT t.id, t.name
            FROM netdb.object_table t
            WHERE t.up IS NULL{states_criterion_tail_t}
            UNION ALL
            SELECT c.id, p.full_name || ' ' || c.name
            FROM netdb.object_table c
            INNER JOIN object_full_names p ON p.id = c.up
            WHERE c.up IS NOT NULL{states_criterion_tail_c}
        )
        SELECT ofn.id, ofn.full_name
        FROM object_full_names ofn
    """)
    object_id_to_full_name = {}
    for object_id, full_name in db_cursor:
        object_id_to_full_name[object_id] = full_name
    return object_id_to_full_name


def obtain_database_entries(db_conn: Any, config: Mapping[str, Any]) \
        -> Dict[str, List[NetworkObjectEntry]]:
    """
    Obtains the allow-list entries from TUNETDB and returns them as a dictionary mapping sanitized
    service names (uppercase with stripped leading and trailing spaces) to lists of
    NetworkObjectEntry instances.
    """
    logger = loggage.get_logger(__name__)

    allowed_object_names = config.get('common', {}).get('allowed_object_names', None)
    allowed_obj_name_dict = {on.upper(): on for on in allowed_object_names} \
        if allowed_object_names is not None else None

    cur = db_conn.cursor()

    # obtain transaction-level read consistency
    db_conn.commit()
    cur.execute("SET TRANSACTION READ ONLY")

    # obtain object full names
    # (we were obtaining spurious entries when performing the recursive subquery,
    # so we had to move this into its own query)
    object_id_to_full_name = obtain_object_id_to_full_name(cur, {TunetDbState.ACTIVE})

    # state: 0=active, 1=template, 2=virtual, 3=request, 4=deleted
    cur.execute(f"""
        SELECT o.id objid, a.id attid, a.class attclass, a.type atttype,
            a.str0 address, a.str1 mask, a.str2 fwservice
        FROM netdb.attribut_table a
        INNER JOIN netdb.object_table o ON o.id = a.obj AND o.state = {TunetDbState.ACTIVE.value}
        WHERE a.state = {TunetDbState.ACTIVE.value}
            AND a.class = 'ALIST' AND a.type IN ('TUFW', 'TUFW6')
    """)
    rows = cur.fetchall()

    # we are done with the database
    db_conn.commit()
    cur.close()

    services_to_entries: Dict[str, List[NetworkObjectEntry]] = {}
    for entry_tuple in rows:
        # unpack
        (
            obj_id, att_id, att_class, att_type, address, mask, fw_service
        ) = entry_tuple

        obj_full_name = object_id_to_full_name.get(obj_id, f"#{obj_id}")

        obj_identifier = f"{obj_full_name} (#{obj_id})"
        att_identifier = f"{att_class}/{att_type} (#{att_id})"

        if address is None or len(address) == 0:
            logger.error(
                f"{obj_identifier}: {att_identifier} entry has no address; ignoring"
            )
            continue

        clean_service = fw_service.strip().upper()
        if allowed_obj_name_dict is not None:
            try:
                clean_service = allowed_obj_name_dict[clean_service]
            except KeyError:
                logger.error(
                    f"{obj_identifier}: {att_identifier} has invalid service {fw_service!r}; "
                    "ignoring"
                )
                continue

        if clean_service not in services_to_entries:
            services_to_entries[clean_service] = []

        if att_type == 'TUFW6':
            # IPv6
            try:
                ip: AnyIPNetwork = ipaddress.IPv6Network(address)
            except ValueError:
                logger.error(
                    f"{obj_identifier}: {att_identifier} entry has invalid IPv6 address "
                    f"{address!r}; ignoring"
                )
                continue

        else:
            # IPv4

            # HACK: clean leading zeroes
            clean_address = LEADING_ZERO_RE.sub('\\1', address)
            if clean_address != address:
                logger.warning(
                    f"{obj_identifier}: cleaning leading zeroes from {att_identifier} IPv4 address "
                    f"{address!r} (gives {clean_address!r})"
                )
                address = clean_address

            if mask is None or len(mask) == 0:
                logger.error(
                    f"{obj_identifier}: {att_identifier} entry with IPv4 address {address!r} does "
                    "not have a subnet mask; ignoring"
                )
                continue

            if mask.lower() == 'host':
                # single-host rule
                try:
                    ip = ipaddress.IPv4Network(address)
                except ValueError:
                    logger.error(
                        f"{obj_identifier}: {att_identifier} has invalid IPv4 address {address!r}; "
                        "ignoring"
                    )
                    continue

            else:
                # subnet rule
                try:
                    ip = ipaddress.IPv4Network(address + "/" + mask)
                except ValueError:
                    logger.error(
                        f"{obj_identifier}: {att_identifier} has invalid IPv4 address {address!r} "
                        f"with mask {mask!r}; ignoring"
                    )
                    continue

        preexisting = [
            noe
            for noe
            in services_to_entries[clean_service]
            if (noe.ip.network_address, noe.ip.prefixlen) == (ip.network_address, ip.prefixlen)
        ]
        if len(preexisting) > 0:
            assert preexisting[0].additional_info is not None
            logger.warning(
                f"duplicate entry: {address!r}/{mask!r} is listed on object "
                f"{preexisting[0].additional_info[0]} attribute {preexisting[0].additional_info[1]} as well "
                f"as object {obj_identifier} attribute {att_identifier}; only processing the first "
                "occurrence"
            )
            continue

        services_to_entries[clean_service].append(NetworkObjectEntry(
            ip,
            obj_full_name,
            identifier=str(att_id),
            additional_info=(obj_identifier, att_identifier),
        ))

    return services_to_entries
