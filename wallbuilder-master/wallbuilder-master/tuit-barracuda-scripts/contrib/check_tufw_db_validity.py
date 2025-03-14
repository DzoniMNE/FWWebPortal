#!/usr/bin/env python3
# Icinga check script for database validity
import argparse
import requests
import sys
import traceback


EXIT_UNKN = 3


def icinga_main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-u', '--url',
        required=True,
        help="URL to web script performing verification."
    )
    args = parser.parse_args()

    response = requests.get(args.url)
    try:
        exit_code = int(response.headers.get('X-Icinga-Exit-Code'))
    except:
        exit_code = EXIT_UNKN

    print(response.text, end='')


def main():
    try:
        icinga_main()
    except Exception:
        # exit with "UNKNOWN" in case of an exception
        print("exception thrown:", file=sys.stderr)
        traceback.print_exc()
        sys.exit(EXIT_UNKN)


if __name__ == '__main__':
    icinga_main()
