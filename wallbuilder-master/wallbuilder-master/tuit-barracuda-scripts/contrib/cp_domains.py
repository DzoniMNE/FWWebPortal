#!/usr/bin/env python3
import argparse
import getpass
from typing import Any, Dict, List, Optional, Union
import urllib.parse
from urllib.parse import urljoin
import warnings
import requests


def urlquote(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def rest_me(
    base_uri: str,
    session_id: Optional[str],
    command: str,
    body: Dict[str, Any],
) -> Dict[str, Any]:
    uri = urljoin(base_uri, urlquote(command))

    headers = {}
    if session_id is not None:
        headers["X-chkp-sid"] = session_id

    response = requests.post(
        uri,
        headers=headers,
        json=body,
        verify=False,
    )
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(
        description="Attempts to resolve the actual addresses behind an address group.",
    )
    parser.add_argument(
        "-b", "--base-uri",
        dest="base_uri", required=True,
        help="The base API URI of the Checkpoint appliance to contact, e.g. \"https://192.168.0.1/web_api/\".",
    )
    parser.add_argument(
        "-u", "--username",
        dest="username", required=True,
        help="The username of the user with which to log in.",
    )
    args = parser.parse_args()

    password = getpass.getpass()

    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # attempt login
    login_body = {"user": args.username, "password": password}
    login_result = rest_me(args.base_uri, None, "login", login_body)
    session_id = login_result["sid"]

    # get domains
    dom_uid_to_name: Dict[str, str] = {}
    try:
        doms_result = rest_me(args.base_uri, session_id, "show-domains", {})
        for dom in doms_result["objects"]:
            dom_uid_to_name[dom['uid']] = dom['name']
            meta_dom_data = dom.get('domain', None)
            if meta_dom_data is not None:
                dom_uid_to_name[meta_dom_data['uid']] = meta_dom_data['name']

        mds_result = rest_me(args.base_uri, session_id, "show-mdss", {})
        for dom in mds_result["objects"]:
            dom_uid_to_name[dom['uid']] = dom['name']
            meta_dom_data = dom.get('domain', None)
            if meta_dom_data is not None:
                dom_uid_to_name[meta_dom_data['uid']] = meta_dom_data['name']

        for uid, name in dom_uid_to_name.items():
            print(f"{uid} {name}")

    finally:
        rest_me(args.base_uri, session_id, "logout", {})


if __name__ == "__main__":
    main()
