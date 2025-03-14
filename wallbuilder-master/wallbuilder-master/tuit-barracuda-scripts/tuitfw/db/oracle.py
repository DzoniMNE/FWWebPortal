from typing import Any, Mapping
from ..common import raise_config_missing_key


def connect_to_database_from_config(cmdb_config: Mapping[str, Any]) -> Any:
    """
    Attempts to connect to a CMDB using the credentials in the given database configuration
    dictionary and returns the connection object.
    """
    try:
        (server, username, password) = (
            cmdb_config['server'],
            cmdb_config['username'],
            cmdb_config['password']
        )
    except KeyError as ex:
        raise_config_missing_key(f"netdb.{ex.args[0]}")

    try:
        import oracledb
        return oracledb.connect(user=username, password=password, dsn=server)
    except ModuleNotFoundError:
        pass

    import cx_Oracle
    return cx_Oracle.connect(username, password, server)
