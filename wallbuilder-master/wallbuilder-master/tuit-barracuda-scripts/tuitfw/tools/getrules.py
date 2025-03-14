"""
# tuitfw.tools.getrules

Obtains firewall rules from a configuration management database and outputs them.

## Configuration

By default, configuration is read from `tuitfw.yaml` in the current working directory. A different
configuration file may be specified using the `-c` command-line option.

An example of a configuration file obtaining rules from TUNETDB:
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

The `cmdb` section is only respected if the `-f`/`--firewall` option is not set.

### firewall section

The `firewall` section stores information on how to access the firewall and which objects to modify.
All options apart from `type` are specific to the firewall module and documented there. For example,
if `type` is set to `barracuda`, see the documentation of `tuitfw.fw.barracuda` for the other
configuration options.

The `firewall` section is only respected if the `-f`/`--firewall` option is set.

## Command line

* `-c FILE`, `--config=FILE`: Specifies the configuration file that should be used. By default,
  `tuitfw.tools.getrules` reads the file `tuitfw.yaml` in the current working directory.

### Output format

The output of this program consists of lines of the format

    SERVICEGROUP\tIPADDRESS\tCOMMENT

for each allow-list entry.

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
    Run the program, reading firewall allow-list entries from the CMDB or the firewall and
    outputting them.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config', metavar='FILE', default=None,
                        help='Specifies the configuration file that should be used.')
    parser.add_argument('-f', '--firewall', dest='firewall', action='store_true',
                        help='Specifies that the firewall should be queried, not the CMDB.')
    loggage.add_argparse_options(parser)
    args = parser.parse_args()

    loggage.configure_from_argparse(args)

    config = common.load_config(args.config)

    if args.firewall:
        # load the allow-list from the firewall
        firewall_module = import_module('..fw.' + config['firewall']['type'], __package__)
        firewall_session = firewall_module.make_api_session(config)
        firewall_session.login()
        obj_to_entries = firewall_session.obtain_firewall_entries()
        firewall_session.consolidate_entries(obj_to_entries)
        firewall_session.logout()

    else:
        # load the new allow-list from the database
        cmdb_module = import_module('..cmdb.' + config['cmdb']['type'], __package__)
        with cmdb_module.connect_to_database_from_config(config) as db_conn: #type: ignore[attr-defined]
            obj_to_entries = cmdb_module.obtain_database_entries(db_conn, config) #type: ignore[attr-defined]

    # write the new allow-list to stdout
    common.output_entries(obj_to_entries, sys.stdout)


if __name__ == '__main__':
    run()
