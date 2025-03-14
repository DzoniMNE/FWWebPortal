"""
# tuitfw.fw.checkpoint

Communicates with a Checkpoint SmartManagement appliance via the Web Services API to obtain and/or
modify rules.

## Configuration

The following configuration stanzas are recognized in the `firewall` section if `type` is set to
`checkpoint`:

* `base_uri` is the base URI of the Checkpoint Web Services API endpoint to contact. The paths to
  the respective endpoints are constructed relative to this base URI.
* `api_key` is the API key with which to login to the Web Services API.
* `domain` specifies the UID of the domain to which to log in. Checkpoint documentation claims that
  the name of the domain may also be passed, but this appears to be a bold-faced lie. To obtain a
  list of domains and their UIDs, you can use the script `cp_domains.py` in the `contrib/`
  directory.
* `net_groups` defines which network groups are modified and how. It is documented later in this
  section.
* `install` defines settings for policy installation (deployment). It is documented later in this
  section. It can be set to `null` if no policy installation should be performed.

#### net_groups subsection

The `net_groups` subsection defines which address groups are modified and how.

* `name_format_ipv4` is a Python format string (`str.format`) to transform a database network
  object name (as listed in `common.allowed_object_names`) to the name of the firewall address
  group to be populated with IPv4 addresses. The database network object name is passed as
  positional argument 0. For example, `"NETDBV4-{0}"` transforms `ALL` into `NETDBV4-ALL`.
* `name_format_ipv6` is the IPv6 counterpart to `name_format_ipv4`.
* `addr_prefix_ipv4` is the prefix to be given to IPv4 address objects administered by this script.
* `addr_prefix_ipv6` is the prefix to be given to IPv6 address objects administered by this script.
* `sentinel_ipv4` is the name of the address object used to ensure that an IPv4 address group is
  never empty.
* `sentinel_ipv6` is the name of the address object used to ensure that an IPv6 address group is
  never empty.

#### install subsection

The `install` subsection defines how the policy is installed. If set to `null`, no installation is
performed.

* `policy_package` is the name of the policy package that should be installed.
* `targets` lists the devices on which the installation is to be performed.
* `additional_options` optionally provides a mapping of additional options to values for the
  installation procedure.
"""
from collections import defaultdict
import datetime
import ipaddress
import time
from typing import AbstractSet, Any, DefaultDict, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import urljoin
import requests
from . import FirewallSession
from .. import loggage
from ..common import AnyIPNetwork, FirewallDiff, NetworkObjectEntry, raise_config_missing_key


LOGIN_VERB = "login"
LOGOUT_VERB = "logout"
LIST_HOSTS_VERB = "show-hosts"
LIST_NETS_VERB = "show-networks"
SHOW_GROUP_VERB = "show-group"
SET_GROUP_VERB = "set-group"
SET_VERB_FORMAT = "set-{0}"
DELETE_VERB_FORMAT = "delete-{0}"
ADD_HOST_VERB = "add-host"
ADD_NET_VERB = "add-network"
SET_SESSION_VERB = "set-session"
PUBLISH_VERB = "publish"
INSTALL_POLICY_VERB = "install-policy"
SHOW_TASK_VERB = "show-task"


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


class NetGroupMetadata:
    """Metadata of a firewall network group."""

    def __init__(self, description: str):
        self.description: str = description

    def __repr__(self) -> str:
        return f"NetGroupMetadata(description={self.description!r})"


class CheckpointFirewallSession(FirewallSession[NetGroupMetadata]):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.session_id: Optional[str] = None


    def consolidate_entries(
        self,
        entries: Dict[str, List[NetworkObjectEntry]],
    ) -> None:
        """
        Consolidates entries to make them more palatable for the firewall. Should not perform any
        external communication, neither with the CMDB nor with the firewall. Optional.

        On Checkpoint, merges the comments of addresses (otherwise, they are replaced there and back
        during every update) and removes duplicate entries.
        """

        addr_to_comments: DefaultDict[AnyIPNetwork, Set[str]] = defaultdict(set)
        addr_to_known_object: Dict[AnyIPNetwork, NetworkObjectEntry] = {}
        addr_to_known_service_groups: DefaultDict[AnyIPNetwork, Set[str]] = defaultdict(set)

        for net_objects in entries.values():
            for net_object in net_objects:
                addr_to_comments[net_object.ip].add(net_object.comment)

        for service_group_name, net_objects in entries.items():
            unique_net_objects: List[NetworkObjectEntry] = []
            for net_object in net_objects:
                if service_group_name in addr_to_known_service_groups[net_object.ip]:
                    # this IP address has already been mentioned in this service group
                    continue
                addr_to_known_service_groups[net_object.ip].add(service_group_name)

                known_object = addr_to_known_object.get(net_object.ip, None)
                if known_object is None:
                    # we have not yet consolidated the hostnames of this entry
                    known_object = net_object
                    known_object.comment = ", ".join(sorted(addr_to_comments[known_object.ip]))
                    addr_to_known_object[known_object.ip] = known_object

                unique_net_objects.append(known_object)

            entries[service_group_name] = unique_net_objects


    def _firewall_request(
        self,
        verb: str,
        body: Dict[str, Any],
        allowed_statuses: Optional[Set[int]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        if allowed_statuses is None:
            allowed_statuses = {200}

        logger = loggage.get_logger(__name__)
        firewall_config = self.config["firewall"]
        ca_cert_location = firewall_config.get("ca_cert_location", False)
        try:
            base_uri = firewall_config["base_uri"]
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        headers: Dict[str, str] = {}
        if self.session_id is not None:
            headers["X-chkp-sid"] = self.session_id

        uri = urljoin(base_uri, verb)
        response = requests.post(
            uri,
            headers=headers,
            json=body,
            verify=ca_cert_location,
        )
        if response.status_code not in allowed_statuses:
            logger.warning(f"API returned HTTP {response.status_code}: {response.text}")
            response.raise_for_status()
        return (response.status_code, response.json())


    def _get_paginated(self, verb: str, body: Dict[str, Any], resp_key: str) -> List[Dict[str, Any]]:
        ret: List[Dict[str, Any]] = []
        offset = 0

        while True:
            my_body = dict(body)
            my_body["offset"] = offset
            _code, response = self._firewall_request(verb, my_body)
            items = response[resp_key]
            if not items:
                break

            ret.extend(items)
            offset += len(items)

        return ret


    def _obtain_name_to_addr(self) -> Dict[str, NetworkObjectEntry]:
        logger = loggage.get_logger(__name__)
        ret: Dict[str, NetworkObjectEntry] = {}

        host_defs = self._get_paginated(LIST_HOSTS_VERB, {"details-level": "full"}, "objects")
        for host_def in host_defs:
            addr_str = host_def.get("ipv4-address", None) or host_def.get("ipv6-address", None)
            if addr_str is None:
                logger.warning(f"host object {host_def['name']!r} has neither 'ipv4-address' nor 'ipv6-address' property; skipping...")
                continue

            ret[host_def["name"]] = NetworkObjectEntry(
                ip=ipaddress.ip_network(addr_str),
                comment=host_def.get("comments", ""),
                additional_info={"type": "host", "name": host_def["name"]},
            )

        net_defs = self._get_paginated(LIST_NETS_VERB, {"details-level": "full"}, "objects")
        for net_def in net_defs:
            addr_str = net_def.get("subnet4", None)
            if addr_str is not None:
                # IPv4 subnet
                mask = net_def.get("subnet-mask", None)
                if mask is None:
                    logger.warning(f"network object {net_def['name']!r} has 'subnet4' property but no 'subnet-mask' property; skipping...")
                    continue
                net: AnyIPNetwork = ipaddress.ip_network(f"{addr_str}/{mask}")
            else:
                addr_str = net_def.get("subnet6", None)
                if addr_str is None:
                    logger.warning(f"network object {net_def['name']!r} has neither 'subnet4' nor 'subnet6' property; skipping...")
                    continue
                prefix = net_def.get("mask-length6", None)
                if prefix is None:
                    logger.warning(f"network object {net_def['name']!r} has 'subnet6' property but no 'mask-length6' property; skipping...")
                    continue
                net = ipaddress.ip_network(f"{addr_str}/{prefix}")

            ret[net_def["name"]] = NetworkObjectEntry(
                ip=net,
                comment=net_def.get("comments", ""),
                additional_info={"type": "network", "name": net_def["name"]},
            )

        return ret


    def _obtain_entries_for_group(
        self,
        net_group_name: str,
        name_to_addr: Mapping[str, NetworkObjectEntry],
    ) -> List[NetworkObjectEntry]:
        logger = loggage.get_logger(__name__)

        _code, response = self._firewall_request(SHOW_GROUP_VERB, {"name": net_group_name})

        entries: List[NetworkObjectEntry] = []
        for member in response["members"]:
            try:
                address = name_to_addr[member["name"]]
            except KeyError as ex:
                logger.warning(
                    f"address {ex.args[0]!r} referenced by net group {net_group_name!r}"
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
                    f" multiple times in the net group {net_group_name!r}"
                )

            entries.append(address)

        return entries


    def _wait_for_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        while True:
            _code, response = self._firewall_request(SHOW_TASK_VERB, {"task-id": task_id})
            if not response["tasks"]:
                return None

            my_task = response["tasks"][0]
            if my_task["status"] != "in progress":
                break

            time.sleep(2)

        return my_task


    def login(self) -> None:
        firewall_config = self.config['firewall']

        try:
            api_key = firewall_config['api_key']
            domain = firewall_config['domain']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        body = {"api-key": api_key, "domain": domain}
        _code, result = self._firewall_request(LOGIN_VERB, body)
        self.session_id = result["sid"]


    def logout(self) -> None:
        self._firewall_request(LOGOUT_VERB, {})
        self.session_id = None


    def obtain_firewall_metadata(
        self,
        address_versions: AbstractSet[int],
    ) -> Dict[str, NetGroupMetadata]:
        """
        Obtains a mapping of address group names to their other metadata.
        """
        firewall_config = self.config['firewall']

        try:
            allowed_names: List[str] = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            net_groups_config = firewall_config['network_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            name_format_ipv4: str = net_groups_config['name_format_ipv4']
            name_format_ipv6: str = net_groups_config['name_format_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.net_groups.{ex.args[0]}")

        net_group_names: List[str] = []
        if 4 in address_versions:
            net_group_names.extend(name_format_ipv4.format(n) for n in allowed_names)
        if 6 in address_versions:
            net_group_names.extend(name_format_ipv6.format(n) for n in allowed_names)

        ret: Dict[str, NetGroupMetadata] = {}
        for net_group_name in net_group_names:
            _code, group_info = self._firewall_request(SHOW_GROUP_VERB, {"name": net_group_name})
            description = group_info.get("description", None)
            ret[net_group_name] = NetGroupMetadata(
                description=description,
            )

        return ret


    def obtain_firewall_entries(self) -> Dict[str, List[NetworkObjectEntry]]:
        firewall_config: Dict[str, Any] = self.config['firewall']

        try:
            net_groups_config: Dict[str, Any] = firewall_config['net_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            allowed_names: List[str] = self.config.get('common', {})['allowed_object_names']
        except KeyError as ex:
            raise_config_missing_key(f"common.{ex.args[0]}")

        try:
            name_format_ipv4: str = net_groups_config['name_format_ipv4']
            name_format_ipv6: str = net_groups_config['name_format_ipv6']
            sentinel_ipv4: str = net_groups_config['sentinel_ipv4']
            sentinel_ipv6: str = net_groups_config['sentinel_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.objects.{ex.args[0]}")

        net_group_names: List[Tuple[str, str]] = []
        net_group_names.extend((n, name_format_ipv4.format(n)) for n in allowed_names)
        net_group_names.extend((n, name_format_ipv6.format(n)) for n in allowed_names)

        # get all addresses
        name_to_addr = self._obtain_name_to_addr()

        services_to_entries: Dict[str, List[NetworkObjectEntry]] = {}
        for service_name, net_group_name in net_group_names:
            try:
                service_entries = services_to_entries[service_name]
            except KeyError:
                service_entries = []
                services_to_entries[service_name] = service_entries

            service_entries.extend(self._obtain_entries_for_group(
                net_group_name,
                name_to_addr,
            ))

            # sentinel entries are a Checkpoint implementation detail
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
            net_groups_config: Dict[str, Any] = firewall_config['net_groups']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.{ex.args[0]}")

        try:
            addr_prefix_ipv4: str = net_groups_config['addr_prefix_ipv4']
            addr_prefix_ipv6: str = net_groups_config['addr_prefix_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.net_groups.{ex.args[0]}")

        if object_name.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
            raise ValueError(
                f"refusing to modify object {object_name!r}; it is not in the list of allowed names"
            )

        v4_group_name = net_groups_config['name_format_ipv4'].format(object_name)
        v6_group_name = net_groups_config['name_format_ipv6'].format(object_name)

        name_to_addr = self._obtain_name_to_addr()

        try_remove_addrs: Set[Tuple[str, str]] = set()
        keep_addrs: Set[Tuple[str, str]] = set()

        for op, old_entry, new_entry in diff:
            some_entry = old_entry or new_entry
            if some_entry is None:
                continue

            if some_entry.ip.version not in address_versions:
                logger.debug(f"{some_entry}: skipping due to disabled IP version")
                continue

            if old_entry is not None and new_entry is not None:
                if old_entry.ip.version != new_entry.ip.version:
                    raise ValueError(
                        f"old_entry {old_entry!r} and new_entry {new_entry!r} differ in IP version!"
                    )

            (group_name, addr_prefix) = {
                4: (v4_group_name, addr_prefix_ipv4),
                6: (v6_group_name, addr_prefix_ipv6),
            }[some_entry.ip.version]

            if op == "/":
                def update_entry(old_entry, new_entry):
                    # directly update comment at address
                    assert old_entry is not None
                    assert old_entry.additional_info is not None
                    assert new_entry is not None

                    entry_type: str = old_entry.additional_info["type"]
                    entry_name: str = old_entry.additional_info["name"]
                    logger.debug(f'updating comment at {old_entry.ip_string} ({entry_name!r})')

                    verb = SET_VERB_FORMAT.format(entry_type)
                    self._firewall_request(
                        verb,
                        {"name": entry_name, "comments": new_entry.comment},
                    )

                    keep_addrs.add((entry_type, entry_name))
                update_entry(old_entry, new_entry)

            if op == "-":
                def remove_entry(old_entry, group_name):
                    assert old_entry is not None
                    assert old_entry.additional_info is not None

                    logger.debug(f'removing {old_entry.ip_string} ({old_entry.additional_info["name"]!r}) from {group_name}')
                    entry_type = old_entry.additional_info["type"]
                    entry_name = old_entry.additional_info["name"]

                    self._firewall_request(
                        SET_GROUP_VERB,
                        {"name": group_name, "members": {"remove": [entry_name]}},
                    )

                    # we might not need this address anymore
                    try_remove_addrs.add((entry_type, entry_name))
                remove_entry(old_entry, group_name)

            if op == "+":
                def add_entry(new_entry, addr_prefix, group_name):
                    assert new_entry is not None

                    logger.debug(f'adding {new_entry.ip_string} to {group_name}')

                    new_entry_type = "network" if new_entry.is_subnet else "host"

                    ip_name = addr_prefix + _sanitize_addr_name(new_entry.ip_string)
                    if ip_name not in name_to_addr:
                        # this address does not exist yet; create it
                        # ignore warnings because of "More than one network has the same IP 128.130.x.y/255.255.255.128"
                        if new_entry.is_subnet:
                            self._firewall_request(
                                ADD_NET_VERB,
                                {
                                    "name": ip_name,
                                    "subnet": new_entry.ip.network_address.compressed,
                                    "mask-length": new_entry.ip.prefixlen,
                                    "comments": new_entry.comment,
                                    "ignore-warnings": True,
                                },
                            )
                        else:
                            self._firewall_request(
                                ADD_HOST_VERB,
                                {
                                    "name": ip_name,
                                    "ip-address": new_entry.ip_string,
                                    "comments": new_entry.comment,
                                    "ignore-warnings": True,
                                },
                            )

                        # remember it in case it crops up later
                        name_to_addr[ip_name] = NetworkObjectEntry(
                            ip=ipaddress.ip_network(new_entry.ip_string),
                            comment=new_entry.comment,
                            additional_info={
                                "type": new_entry_type,
                                "name": ip_name,
                            },
                        )

                    # add it as a member
                    self._firewall_request(
                        SET_GROUP_VERB,
                        {"name": group_name, "members": {"add": [ip_name]}},
                    )

                    # we are going to need it after all
                    keep_addrs.add((new_entry_type, ip_name))
                add_entry(new_entry, addr_prefix, group_name)

        # remove old addresses
        try_remove_addrs.difference_update(keep_addrs)
        for type_to_remove, name_to_remove in try_remove_addrs:
            logger.debug(f"deleting removed {type_to_remove} object {name_to_remove!r}")

            verb = DELETE_VERB_FORMAT.format(type_to_remove)
            del_code, del_resp = self._firewall_request(
                verb,
                {"name": name_to_remove},
                {200, 400, 409},
            )
            if del_code == 400:
                if any(
                    "is used by the following object" in warning["message"]
                    for warning in del_resp["warnings"]
                ):
                    logger.debug("object is still in use")
                else:
                    logger.warning(f"failed to delete {type_to_remove} object {name_to_remove!r}: {del_resp}")
            elif del_code == 409:
                if "because it is referenced by other objects" in del_resp["message"]:
                    logger.debug("object is still in use")
                else:
                    logger.warning(f"failed to delete {type_to_remove} object {name_to_remove!r}: {del_resp}")


    def construct_full_firewall_lists(
        self,
        services_lists: Mapping[str, List[NetworkObjectEntry]],
        objects_metadata: Mapping[str, NetGroupMetadata],
        address_versions: AbstractSet[int],
    ) -> Mapping[str, Mapping[str, Any]]:
        logger = loggage.get_logger(__name__)

        net_groups_config = self.config['firewall']['net_groups']

        try:
            addr_prefix_ipv4: str = net_groups_config['addr_prefix_ipv4']
            addr_prefix_ipv6: str = net_groups_config['addr_prefix_ipv6']
        except KeyError as ex:
            raise_config_missing_key(f"firewall.net_groups.{ex.args[0]}")

        names_to_final_groups: Dict[str, Any] = {}
        names_to_addresses: Dict[str, Any] = {}

        # prepare lists
        for name, metadata in objects_metadata.items():
            names_to_final_groups[name] = {
                "name": name,
                "comments": metadata.description,
                "members": [],
            }

        for service, entries in services_lists.items():
            if service.upper() not in {an.upper() for an in self.config['common']['allowed_object_names']}:
                raise ValueError(
                    f"refusing to modify network object {service!r}; it is not in the list of"
                    " allowed names"
                )

            for entry in sorted(entries, key=lambda e: e.comparison_key):
                if entry.ip.version not in address_versions:
                    logger.debug(f"{entry}: skipping due to disabled IP version")
                    continue

                name_format = net_groups_config[f'name_format_ipv{entry.ip.version}']
                name = name_format.format(service)

                this_addr_prefix = {
                    4: addr_prefix_ipv4,
                    6: addr_prefix_ipv6,
                }[entry.ip.version]
                ip_name = this_addr_prefix + _sanitize_addr_name(entry.ip_string)

                names_to_final_groups[name]['members'].append(ip_name)

                addr = {
                    "name": ip_name,
                    "comments": entry.comment,
                }
                if entry.is_subnet:
                    addr["subnet"] = entry.ip.network_address.compressed
                    addr["mask-length"] = f"{entry.ip.prefixlen}"
                else:
                    addr["ip-address"] = entry.ip.network_address.compressed
                names_to_addresses[ip_name] = addr

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
            "the Checkpoint API is not conducive to full-list replacement; please use the standard"
            " operating mode"
        )


    def commit_changes(self) -> None:
        """
        Commits all pending changes, activating them on the firewall.
        """
        logger = loggage.get_logger(__name__)

        session_name = datetime.datetime.now().strftime('tuitfw_%Y-%m-%d_%H:%M:%S')
        session_description = "tuitfw automatic rule update from CMDB"

        logger.debug(f"naming session {session_name!r}")

        self._firewall_request(
            SET_SESSION_VERB,
            {
                "new-name": session_name,
                "description": session_description,
            },
        )

        logger.debug("publishing changes")

        _code, response = self._firewall_request(PUBLISH_VERB, {})
        publish_task = response["task-id"]
        done_task = self._wait_for_task(publish_task)

        if done_task is None:
            logger.error("publishing task disappeared!")
            return

        if done_task["status"] in ("succeeded with warnings", "partially succeeded"):
            logger.warning(f"publishing task {done_task['status']}: {done_task['task-details']}")
        elif done_task["status"] == "failed":
            logger.error(f"publishing task failed: {done_task['task-details']}")
            return
        elif done_task["status"] == "succeeded":
            logger.debug(f"publishing task succeeded: {done_task['task-details']}")
        else:
            logger.warning(f"publishing task in unknown state {done_task['status']!r}: {done_task['task-details']}")

        install_config = self.config["firewall"]["install"]
        if install_config is None:
            # don't install
            return

        logger.debug("installing policy")

        body = {
            "policy-package": install_config["policy_package"],
            "targets": install_config["targets"],
        }
        body.update(install_config.get("additional_options", {}))

        _code, response = self._firewall_request(INSTALL_POLICY_VERB, body)
        install_task = response["task-id"]
        done_task = self._wait_for_task(install_task)

        if done_task is None:
            logger.error("policy installation task disappeared!")
            return

        if done_task["status"] in ("succeeded with warnings", "partially succeeded"):
            logger.warning(f"policy installation {done_task['status']}: {done_task!r}")
        elif done_task["status"] == "failed":
            logger.error(f"policy installation failed: {done_task!r} -- try performing installation manually via SmartConsole")
            return
        elif done_task["status"] == "succeeded":
            logger.debug(f"policy installaton succeeded: {done_task!r}")
        else:
            logger.warning(f"policy installation in unknown state {done_task['status']!r}: {done_task!r}")


def make_api_session(config: Dict[str, Any]) -> CheckpointFirewallSession:
    return CheckpointFirewallSession(config)
