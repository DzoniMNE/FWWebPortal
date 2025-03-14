import ipaddress
from typing import Any, cast, Dict, Iterable, List, Mapping, Optional, TextIO, Tuple, Union
import yaml


DEFAULT_CONFIG_FILE_NAME = "tuitfw.yaml"
TAB_DELIMITED_FILE_BAD_CHARS = "\t\r\n"

AnyIPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
AnyIPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
AnyIPAddressOrNetwork = Union[AnyIPAddress, AnyIPNetwork]


class NetworkObjectEntry:
    """A network object, consisting of a IP network and a comment."""

    def __init__(self, ip: AnyIPAddressOrNetwork, comment: str, identifier: Optional[str] = None, additional_info: Any = None):
        if hasattr(ip, 'netmask'):
            ip_net = cast(AnyIPNetwork, ip)
        else:
            ip_net = ipaddress.ip_network(ip)

        self.ip = ip_net
        self.comment = comment
        self.identifier = identifier # used to differentiate sources of entries
        self.additional_info = additional_info

    def __repr__(self) -> str:
        return f"NetworkObjectEntry(ip={self.ip!r}, comment={self.comment!r})"

    def __str__(self) -> str:
        return f"{self.ip_string} {self.comment!r}"

    @property
    def is_subnet(self) -> bool:
        return self.ip.prefixlen < self.ip.max_prefixlen

    @property
    def ip_string(self) -> str:
        if self.is_subnet:
            ip_text = f"{self.ip.network_address.compressed}/{self.ip.prefixlen}"
        else:
            ip_text = self.ip.network_address.compressed
        return ip_text

    @property
    def comparison_key(self) -> Tuple[int, bytes, int]:
        return (self.ip.version, self.ip.network_address.packed, self.ip.prefixlen)


FirewallDiff = List[Tuple[str, Optional[NetworkObjectEntry], Optional[NetworkObjectEntry]]]


def load_config(file_name: Optional[str] = None) -> Mapping[str, Any]:
    """
    Loads the configuration file with the given name and returns the result of parsing it as a YAML
    file.
    """
    if file_name is None:
        file_name = DEFAULT_CONFIG_FILE_NAME

    with open(file_name, 'rb') as config_file:
        return yaml.safe_load(config_file)


def raise_config_missing_key(key: str, addendum: Optional[str] = None) -> None:
    """Raises an exception that the configuration key with a given name is missing."""
    buf = f"configuration is missing key {key!r}"
    if addendum is not None:
        buf = "".join((buf, " ", addendum))
    raise KeyError(buf)


def obtain_file_entries(file_object: TextIO) -> Dict[str, List[NetworkObjectEntry]]:
    """
    Obtains the allow-list entries from the given file and returns them as a dictionary mapping
    sanitized service names (uppercase with stripped leading and trailing spaces) to lists of
    NetworkObjectEntry instances.
    """
    ret: Dict[str, List[NetworkObjectEntry]] = {}
    for (zero_line_number, line) in enumerate(file_object):
        line_number = zero_line_number + 1
        line = line.rstrip("\n\r")

        if len(line) == 0:
            # skip empty lines
            continue

        pieces = line.split("\t")
        if len(pieces) != 3:
            raise ValueError(
                f"line {line_number} contains invalid number of fields (got {len(pieces)}, "
                f"expected 3)"
            )

        service, ip_address_string, comment = pieces
        service = service.strip().upper()
        ip_address = ipaddress.ip_network(ip_address_string)

        if service not in ret:
            ret[service] = []

        ret[service].append(NetworkObjectEntry(ip_address, comment))

    return ret


def diff_firewall_entries(old_entries: List[NetworkObjectEntry],
                          new_entries: List[NetworkObjectEntry]) -> FirewallDiff:
    """
    Calculates the differences between the two lists of NetworkObjectEntry instances and returns
    a list of tuples enumerating the changes to be implemented to synchronize the first list with
    the second list.
    """
    old_sorted = sorted(old_entries, key=lambda noe: noe.comparison_key)
    new_sorted = sorted(new_entries, key=lambda noe: noe.comparison_key)

    diff: List[Tuple[str, Optional[NetworkObjectEntry], Optional[NetworkObjectEntry]]] = []

    old_iter, new_iter = iter(old_sorted), iter(new_sorted)

    old_entry, new_entry = next(old_iter, None), next(new_iter, None)
    if old_entry is not None and new_entry is not None:
        while True:
            if old_entry.comparison_key < new_entry.comparison_key:
                # later entry in new than in old
                # => delete entry in old
                diff.append(('-', old_entry, None))

                # => get next old entry
                old_entry = next(old_iter, None)
                if old_entry is None:
                    break

            elif old_entry.comparison_key > new_entry.comparison_key:
                # later entry in old than in new
                # => add entry in new
                diff.append(('+', None, new_entry))

                # => get next new entry
                new_entry = next(new_iter, None)
                if new_entry is None:
                    break

            else:
                # equal
                if old_entry.comment != new_entry.comment:
                    # comment has changed; replace
                    diff.append(('/', old_entry, new_entry))

                # leave alone otherwise

                old_entry = next(old_iter, None)
                new_entry = next(new_iter, None)
                if old_entry is None or new_entry is None:
                    break


    # one of the lists has ended
    # process the other
    # => if there are items left in old, delete them
    if old_entry is not None:
        while True:
            diff.append(('-', old_entry, None))
            old_entry = next(old_iter, None)
            if old_entry is None:
                break

    # => if there are items left in new, add them
    if new_entry is not None:
        while True:
            diff.append(('+', None, new_entry))
            new_entry = next(new_iter, None)
            if new_entry is None:
                break

    # and we are done
    return diff


def diff_firewall_services(old_services: Mapping[str, List[NetworkObjectEntry]],
                           new_services: Mapping[str, List[NetworkObjectEntry]]) \
        -> Dict[str, FirewallDiff]:
    """
    Calculates the differences between the two mappings of service names mapped to lists of
    NetworkObjectEntry instances and returns a dictionary mapping service names to lists of tuples
    enumerating the changes to be implemented to synchronize the respective first list with the
    respective second list.
    """
    diffs = {}
    for service_name, old_entries in old_services.items():
        new_entries = new_services.get(service_name, [])

        diff = diff_firewall_entries(old_entries, new_entries)
        diffs[service_name] = diff

    return diffs


def output_entries(entries: Mapping[str, Iterable[NetworkObjectEntry]],
                   file_object: TextIO) -> None:
    """
    Outputs the allow-list entries into a file in the format accepted by `obtain_file_entries`.
    """

    for (service, service_entries) in sorted(entries.items(), key=lambda kv: kv[0]):
        # ensure the service name contains no bad characters
        for bad_char in TAB_DELIMITED_FILE_BAD_CHARS:
            if bad_char in service:
                raise ValueError(
                    f"cannot write allow-list to file: name of service {service!r} contains "
                    f"disallowed character {bad_char!r}"
                )

        for entry in sorted(service_entries, key=lambda noe: noe.comparison_key):
            # ensure the comment contains no bad characters
            for bad_char in TAB_DELIMITED_FILE_BAD_CHARS:
                if bad_char in entry.comment:
                    raise ValueError(
                        f"cannot write allow-list to file: comment {entry.comment!r} contains "
                        f"disallowed character {bad_char!r}"
                    )

            print(f"{service}\t{entry.ip_string}\t{entry.comment}", file=file_object)


def output_diff(services_diffs: Mapping[str, FirewallDiff], file_object: TextIO) -> None:
    """
    Outputs the differences between two allow-lists into a file.
    """

    for (service, diff) in services_diffs.items():
        # ensure the service name contains no bad characters
        for bad_char in TAB_DELIMITED_FILE_BAD_CHARS:
            if bad_char in service:
                raise ValueError(
                    f"cannot write diff to file: name of service {service!r} contains disallowed "
                    f"character {bad_char!r}"
                )

        for (op, old_entry, new_entry) in diff:
            old_ip, old_comment = (old_entry.ip_string, old_entry.comment) \
                if old_entry is not None else ("", "")
            new_ip, new_comment = (new_entry.ip_string, new_entry.comment) \
                if new_entry is not None else ("", "")

            for bad_char in TAB_DELIMITED_FILE_BAD_CHARS:
                for comment in (old_comment, new_comment):
                    if bad_char in comment:
                        raise ValueError(
                            f"cannot write diff to file: comment {comment!r} contains disallowed "
                            f"character {bad_char!r}"
                        )

            print(f"{service}\t{op}\t{old_ip}\t{old_comment}\t{new_ip}\t{new_comment}",
                  file=file_object)
