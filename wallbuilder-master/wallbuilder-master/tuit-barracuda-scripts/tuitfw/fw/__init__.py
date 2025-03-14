import json
from typing import AbstractSet, Any, Dict, Generic, List, Mapping, TextIO, TypeVar
from ..common import FirewallDiff, NetworkObjectEntry


AGMT = TypeVar("AGMT")


class FirewallSession(Generic[AGMT]):
    """
    A generic session connecting to a firewall. Requires further specialization depending on
    vendor-specific requirements.

    The class is generic with regard to the type used for address group metadata. Descendant classes
    are expected to fix a concrete type.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config: Dict[str, Any] = config


    def login(self) -> None:
        """
        Performs the necessary authentication to open a session to the firewall and stores the
        necessary state information within this object.

        The default implementation does nothing; this is sufficient for vendors whose APIs pass a
        constant authentication string with every request.
        """


    def consolidate_entries(self, entries: Dict[str, List[NetworkObjectEntry]]) -> None:
        """
        Consolidates entries to make them more palatable for the firewall. Should not perform any
        external communication, neither with the CMDB nor with the firewall.

        The default implementation does nothing.
        """


    def obtain_firewall_metadata(self, address_versions: AbstractSet[int]) -> Dict[str, AGMT]:
        """
        Obtains a mapping of address group names to their other metadata.
        """
        raise NotImplementedError()


    def obtain_firewall_entries(self) -> Dict[str, List[NetworkObjectEntry]]:
        """
        Obtains the allow-list entries from the firewall and returns them as a dictionary mapping
        sanitized service names (uppercase with stripped leading and trailing spaces) to lists of
        NetworkObjectEntry instances.
        """
        raise NotImplementedError()


    def implement_diff_on_firewall(
        self,
        diff: FirewallDiff,
        object_name: str,
        address_versions: AbstractSet[int],
    ) -> None:
        """
        Update the given firewall allow-list object using the given difference list.
        """
        raise NotImplementedError()


    def construct_full_firewall_lists(
        self,
        services_lists: Mapping[str, List[NetworkObjectEntry]],
        objects_metadata: Mapping[str, AGMT],
        address_versions: AbstractSet[int],
    ) -> Mapping[str, Mapping[str, Any]]:
        """
        Constructs full network object definitions to be submitted to the firewall's API.
        """
        raise NotImplementedError()


    @staticmethod
    def dump_full_firewall_lists(
        names_to_lists: Mapping[str, Mapping[str, Any]],
        out_file: TextIO,
    ) -> None:
        json.dump(names_to_lists, out_file, indent=2)


    @property
    def can_replace_lists(self) -> bool:
        raise NotImplementedError()


    def replace_lists_on_firewall(self, names_to_objects: Mapping[str, Mapping[str, Any]]) -> None:
        """
        Replace the lists on the firewall with the given lists.
        """
        raise NotImplementedError()


    def commit_changes(self) -> None:
        """
        Commits all pending changes, activating them on the firewall.

        The default implementation does nothing; this is sufficient for vendors whose API
        autocommits.
        """


    def logout(self) -> None:
        """
        Terminates the session previously opened with `login()`.

        The default implementation does nothing; this is sufficient for vendors whose APIs pass a
        constant authentication string with every request.
        """
