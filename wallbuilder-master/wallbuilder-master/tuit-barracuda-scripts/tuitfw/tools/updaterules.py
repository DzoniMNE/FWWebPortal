"""
# tuitfw.tools.updaterules

Obtains firewall rules from a configuration management database and synchronizes them with a
firewall.

## Configuration

By default, configuration is read from `tuitfw.yaml` in the current working directory. A different
configuration file may be specified using the `-c` command-line option.

An example of a configuration file obtaining rules from TUNETDB and synchronizing them to a
Barracuda firewall:
```
common:
  allowed_object_names:
    - ALL
    - FTP
    - POPIMAP
    - REMOTE
    - SSH
    - WWW
cmdb:
  type: tunetdb
  server: opaka.kom.tuwien.ac.at:1521/XE
  username: kom
  password: N0T7H3AC7U4LP4S5W0RD
firewall:
  type: barracuda
  base_uri: https://fwcc-box.kom.tuwien.ac.at:8443/
  username: netdb
  password: Th1sP4ssw0rdIsF4keT00!
  objects:
    type: cc-global
    name_format_ipv4: "NETDBV4-{0}"
    name_format_ipv6: "NETDBV6-{0}"
```

### common section

The `common` section stores processing information interesting to both CMDB and firewall.

* `allowed_object_names` is a list of network object names that are accepted for processing by this
  script. If a firewall rule entry is found in the database whose network object name does not,
  case-insensitively, match one of the names specified here, a warning is output and the attribute
  is skipped.

### cmdb section

The `cmdb` section stores information on how to access the configuration management database (CMDB).
All options apart from `type` are specific to the CMDB module and documented there. For example, if
`type` is set to `tunetdb`, see the documentation of `tuitfw.cmdb.tunetdb` for the other
configuration options.

### firewall section

The `firewall` section stores information on how to access the firewall and which objects to modify.
All options apart from `type` are specific to the firewall module and documented there. For example,
if `type` is set to `barracuda`, see the documentation of `tuitfw.fw.barracuda` for the other
configuration options.

## Command line

* `-4`, `--ipv4-only`: Limits processing to IPv4 addresses only.
* `-6`, `--ipv6-only`: Limits processing to IPv6 addresses only.
* `-c FILE`, `--config=FILE`: Specifies the configuration file that should be used. By default,
  `tuitfw.tools.updaterules` reads the file `tuitfw.yaml` in the current working directory.
* `-d`, `--dry-run`: Compares the database list with the list on the firewall and outputs the
  result, but does not actually update the firewall list to match the database list.
* `--replace-objects`: Pushes the full network objects to the firewall instead of calculating and
  only pushing the differences.
* `--input-cmdb=FILE`: Reads the CMDB allow-list from FILE instead of querying the CMDB. By default,
  the CMDB is queried.
* `--output-cmdb=FILE`: Outputs the allow-list obtained from the CMDB into FILE. By default, the
  CMDB allow-list is not output into a file.
* The following options can be used in conjunction with `--replace-objects`:
  * `--output-objects=FILE`: Outputs the assembled network objects in the format accepted by the
    firewall into FILE.
* The following options can be used when `--replace-objects` is not specified:
  * `--output-firewall=FILE`: Outputs the allow-list obtained from the firewall into FILE, in the
    state before any synchronization is performed. By default, the firewall allow-list is not output
    into a file.
  * `--output-diff=FILE`: Outputs the differences between the allow-list obtained from the CMDB and
    the allow-list obtained from the firewall into FILE. By default, the differences are not output
    into a file.

### Input/output file format

The files output by the `--output-cmdb` and `--output-firewall` options and read by the
`--input-cmdb` option consist of lines of the format

    SERVICEGROUP\tIPADDRESS\tCOMMENT

for each allow-list entry. The file output by the `--output-diff` option consists of lines of the
format

    OPERATION\tSERVICEGROUP\tOLDADDRESS\tOLDCOMMENT\tNEWADDRESS\tNEWCOMMENT

\t represents a tab character (U+0009). (It follows that none of the field values may contain a tab
character.) Lines are terminated using Windows newlines (U+000D followed by U+000A) and the files
are encoded in UTF-8 (without a preamble).
"""

import argparse
from importlib import import_module
import sys
from .. import common, loggage


def run() -> None:
    """
    Run the program, reading firewall allow-list entries from a CMDB and synchronizing them onto
    a firewall.
    """
    parser = argparse.ArgumentParser()
    addr_group = parser.add_mutually_exclusive_group()
    addr_group.add_argument('-4', '--ipv4-only', dest='ipv4_only', action='store_true', default=False,
                            help='Limits processing to IPv4 addresses only.')
    addr_group.add_argument('-6', '--ipv6-only', dest='ipv6_only', action='store_true', default=False,
                            help='Limits processing to IPv6 addresses only.')
    parser.add_argument('-c', '--config', dest='config', metavar='FILE', default=None,
                        help='Specifies the configuration file that should be used.')
    parser.add_argument('-d', '--dry-run', dest='dry_run', action='store_true', default=False,
                        help='Does not update the firewall list.')
    parser.add_argument('--output-cmdb', dest='output_cmdb', metavar='FILE', default=None,
                        help='Outputs the list of addresses from the CMDB into FILE after fetching them.')
    parser.add_argument('--output-firewall', dest='output_firewall', metavar='FILE', default=None,
                        help='Outputs the list of addresses from the firewall (before any synchronization is performed) into FILE after fetching them.')
    parser.add_argument('--output-diff', dest='output_diff', metavar='FILE', default=None,
                        help='Outputs the list of differences between the CMDB list and the firewall list into FILE after calculating it.')
    parser.add_argument('--input-cmdb', dest='input_cmdb', metavar='FILE', default=None,
                        help='Reads the list of addresses from FILE instead of querying the CMDB.')
    parser.add_argument('--replace-objects', dest='replace_objects', action='store_true', default=False,
                        help='Pushes the full objects to the firewall instead of calculating and transmitting the differences.')
    parser.add_argument('--output-objects', dest='output_objects', metavar='FILE', default=None,
                        help='Outputs the new firewall objects in the firewall-native format into FILE after they have been assembled.')
    parser.add_argument('-m', '--history-message', dest='history_message', metavar='MESSAGE', default="no message specified",
                        help='The message used to annotate this update in the update history.')
    loggage.add_argparse_options(parser)
    args = parser.parse_args()

    loggage.configure_from_argparse(args)

    module_name = __name__ if __name__ != '__main__' else 'tuitfw.tools.updaterules'
    logger = loggage.get_logger(module_name)

    if args.replace_objects:
        if args.output_firewall is not None or args.output_diff is not None:
            print("'--replace-objects' may not be combined with '--output-firewall' or '--output-diff'",
                  file=sys.stderr)
            parser.print_usage()
            sys.exit(1)
    else:
        if args.output_objects is not None:
            print("'--output-objects' can only be used in conjunction with '--replace-objects'",
                  file=sys.stderr)
            parser.print_usage()
            sys.exit(1)

    if args.ipv4_only:
        address_versions = {4}
    elif args.ipv6_only:
        address_versions = {6}
    else:
        address_versions = {4, 6}

    config = common.load_config(args.config)

    logger.debug(f"firewall is of type {config['firewall']['type']!r}")
    firewall_module = import_module('..fw.' + config['firewall']['type'], __package__)
    firewall_session = firewall_module.make_api_session(config)
    logger.debug("logging in to firewall")
    firewall_session.login()

    if args.input_cmdb is not None:
        logger.debug(f"loading new allow-list from {args.input_cmdb!r}")
        with open(args.input_cmdb, "r", encoding="utf-8") as f:
            obj_to_database_entries = common.obtain_file_entries(f)
    else:
        logger.debug(f"loading new allow-list from CMDB of type {config['cmdb']['type']!r}")
        cmdb_module = import_module('..cmdb.' + config['cmdb']['type'], __package__)
        with cmdb_module.connect_to_database_from_config(config) as db_conn: #type: ignore[attr-defined]
            obj_to_database_entries = cmdb_module.obtain_database_entries(db_conn, config) #type: ignore[attr-defined]
            firewall_session.consolidate_entries(obj_to_database_entries)

    if args.output_cmdb is not None:
        logger.debug(f"writing new allow-list to {args.output_cmdb!r}")
        with open(args.output_cmdb, "w", encoding="utf-8", newline="\r\n") as f:
            common.output_entries(obj_to_database_entries, f)

    if args.replace_objects:
        logger.debug("obtaining metadata of firewall allow-lists")
        firewall_metadata = firewall_session.obtain_firewall_metadata(address_versions)
        logger.debug(f"known firewall allow-lists: {sorted(firewall_metadata.keys())!r}")

        logger.debug("constructing firewall allow-lists")
        prepared_objects = firewall_session.construct_full_firewall_lists(
            obj_to_database_entries,
            firewall_metadata,
            address_versions
        )

        if args.output_objects is not None:
            logger.debug(f"writing new firewall allow-lists to {args.output_objects!r}")
            with open(args.output_objects, 'w', encoding="utf-8", newline="\r\n") as f:
                firewall_session.dump_full_firewall_lists(prepared_objects, f) #type: ignore[attr-defined]

        if not args.dry_run:
            logger.debug("replacing firewall allow-lists")
            firewall_session.replace_lists_on_firewall(prepared_objects)
        else:
            logger.debug("dry run; not replacing firewall allow-lists")

    else:
        logger.debug("obtaining current firewall allow-list entries")
        obj_to_firewall_entries = firewall_session.obtain_firewall_entries()

        if args.output_firewall is not None:
            logger.debug(f"writing current firewall allow-list entries to {args.output_firewall!r}")
            with open(args.output_firewall, "w", encoding="utf-8", newline="\r\n") as f:
                common.output_entries(obj_to_firewall_entries, f)

        # calculate the changes
        logger.debug("calculating changes between current and new allow-lists")
        diffs = common.diff_firewall_services(obj_to_firewall_entries, obj_to_database_entries)

        if args.output_diff is not None:
            logger.debug(
                f"writing differences between current and new allow-lists to {args.output_diff!r}"
            )
            with open(args.output_diff, "w", encoding="utf-8", newline="\r\n") as f:
                common.output_diff(diffs, f)


        for (object_name, diff) in sorted(diffs.items()):
            # log the differences
            if len(diff) == 0:
                logger.info(f'{object_name}: no change')
            else:
                logger.info(f'{object_name}:')
                for (op, old_entry, new_entry) in diff:
                    if op == '+':
                        logger.info(f'  + {new_entry}')
                    elif op == '-':
                        logger.info(f'  - {old_entry}')
                    elif op == '/':
                        logger.info(f'  / {old_entry} -> {new_entry}')
                    else:
                        raise ValueError(f"Unknown operation {op!r}!")


            if not args.dry_run:
                logger.debug(f"implementing {object_name} changes on firewall")
                # implement on the firewall
                firewall_session.implement_diff_on_firewall(
                    diff, object_name, address_versions
                )
            else:
                logger.debug(f"dry run; not implementing {object_name} changes on firewall")

    if not args.dry_run:
        # commit changes
        firewall_session.commit_changes()

        # obtain current firewall state and write history
        history_config = config.get('history', None)
        if history_config is not None:
            logger.debug("adding changes to history")
            history_module = import_module('..history.' + history_config['type'], __package__)

            # obtain current (updated) entries from firewall
            fresh_obj_to_firewall_entries = firewall_session.obtain_firewall_entries()

            # remember them
            history_module.remember( #type: ignore[attr-defined]
                fresh_obj_to_firewall_entries,
                history_config,
                args.history_message,
            )

    logger.debug("logging out of firewall")
    firewall_session.logout()


if __name__ == '__main__':
    run()
